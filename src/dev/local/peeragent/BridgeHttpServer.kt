package dev.local.peeragent

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

interface CommandSink {
    fun play()
    fun pause()
    fun next()
    fun prev()
    fun seekForward()
    fun seekBackward()
    fun seekTo(positionMs: Long)
    fun volumeUp()
    fun volumeDown()
    fun statusJson(): String
    fun artJpeg(): ByteArray?
}

/**
 * WireGuard-facing. This used to be loopback-only, with peer-agent (a Termux
 * python3 process on the tunnel address) proxying named actions in over
 * 127.0.0.1 and being the whole trust boundary. peer-agent has been retired
 * from the phone - it was doing nothing here but hold a perimeter in a
 * process Android kills whenever Termux is closed - so this server now takes
 * the tunnel traffic directly and carries that perimeter itself:
 *
 *   1. Bound to 0.0.0.0, not the tunnel address. An unprivileged app cannot
 *      enumerate or reliably bind WireGuard's VpnService tun interface, and a
 *      wildcard socket also survives the tunnel dropping and reconnecting.
 *      The source-address check below is what an interface-scoped firewall
 *      rule does on the Linux peers; the phone cannot have one of those.
 *   2. Source address must be loopback or 10.10.0.0/24. On the tunnel the
 *      source address is a WireGuard-authenticated credential; off it (same
 *      WiFi, weak host model) the packet is dropped here.
 *   3. POST/GET only; anything else (OPTIONS included) -> 405 with no CORS
 *      headers. Plus a required non-simple header `X-Peer-Agent: 1`, and any
 *      request carrying `Origin` is refused. Every WireGuard peer also runs a
 *      browser, and a web page can make that browser fire requests at
 *      10.10.0.x; this forces a CORS preflight the server fails, and blocks
 *      the header-less <img>/<form> paths outright.
 *
 * There is deliberately no token: WireGuard already authenticates who may
 * reach the tunnel. These checks only cover what WireGuard structurally
 * cannot - the confused-deputy browser case, and the socket being reachable
 * off-tunnel on a firewall-less host.
 */
class BridgeHttpServer(
    private val port: Int,
    private val sink: CommandSink,
    private val log: (String) -> Unit,
    private val adb: AdbToggle? = null,
    private val wireGuardActive: (() -> Boolean)? = null,
) {
    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var running = false
    private val pool = Executors.newCachedThreadPool()
    private val sseClients = CopyOnWriteArrayList<OutputStream>()

    fun start() {
        running = true
        pool.execute { acceptLoop() }
        pool.execute { keepaliveLoop() }
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: IOException) {}
        for (os in sseClients) try { os.close() } catch (_: IOException) {}
        sseClients.clear()
        pool.shutdownNow()
    }

    fun broadcast(json: String) {
        val frame = "data: $json\n\n".toByteArray(StandardCharsets.UTF_8)
        for (os in sseClients) {
            try {
                synchronized(os) { os.write(frame); os.flush() }
            } catch (e: IOException) {
                sseClients.remove(os)
            }
        }
    }

    private fun keepaliveLoop() {
        try {
            while (running) {
                try { Thread.sleep(30_000) } catch (_: InterruptedException) { return }
                val ping = ": ping\n\n".toByteArray(StandardCharsets.UTF_8)
                for (os in sseClients) {
                    try {
                        synchronized(os) { os.write(ping); os.flush() }
                    } catch (e: Exception) {
                        sseClients.remove(os)
                    }
                }
            }
        } catch (t: Throwable) {
            log("keepaliveLoop failed: ${t.javaClass.name}: ${t.message}")
        }
    }

    private fun acceptLoop() {
        // Runs on a pool thread: an uncaught exception here does not go
        // through onCreate()'s try/catch at all - it kills the whole process
        // via Android's default uncaught-exception handler, same as an
        // uncaught exception on the main thread would. Every thread entry
        // point in this class must therefore catch Throwable, not just the
        // exception types the "expected" failure modes would raise.
        try {
            val bindAddr = InetAddress.getByName("0.0.0.0")
            val ss = ServerSocket(port, 50, bindAddr)
            serverSocket = ss
            log("listening on ${bindAddr.hostAddress}:$port (source-restricted to 10.10.0.0/24 + loopback)")
            while (running) {
                val client = try {
                    ss.accept()
                } catch (e: Exception) {
                    if (running) log("accept error: ${e.javaClass.simpleName}: ${e.message}")
                    break
                }
                pool.execute { handleClient(client) }
            }
        } catch (t: Throwable) {
            log("acceptLoop failed: ${t.javaClass.name}: ${t.message}")
        }
    }

    // 10.10.0.0/24 or loopback. Handles IPv4 and IPv4-mapped IPv6 so a
    // "::ffff:10.10.0.2" peer is not silently rejected.
    private fun sourceAllowed(addr: InetAddress?): Boolean {
        if (addr == null) return false
        if (addr.isLoopbackAddress) return true
        val raw = addr.address
        val v4 = when {
            raw.size == 4 -> raw
            raw.size == 16 && isV4Mapped(raw) -> raw.copyOfRange(12, 16)
            else -> return false
        }
        return (v4[0].toInt() and 0xFF) == 10 &&
            (v4[1].toInt() and 0xFF) == 10 &&
            (v4[2].toInt() and 0xFF) == 0
    }

    private fun isV4Mapped(b: ByteArray): Boolean {
        for (i in 0..9) if (b[i].toInt() != 0) return false
        return (b[10].toInt() and 0xFF) == 0xFF && (b[11].toInt() and 0xFF) == 0xFF
    }

    private fun handleClient(client: Socket) {
        try {
            client.soTimeout = 10_000

            if (!sourceAllowed(client.inetAddress)) {
                log("deny: off-net source ${client.inetAddress?.hostAddress}")
                respondAndClose(client, 403, "text/plain", "forbidden")
                return
            }

            // Read byte-at-a-time (not a BufferedReader) so nothing past the
            // blank line that ends the headers is ever consumed - a POST with
            // a binary body (the privileged-install endpoint) reads exactly
            // Content-Length raw bytes straight off this same stream next,
            // and a BufferedReader's internal buffering would silently eat
            // the start of that body while parsing headers.
            val rawIn = client.getInputStream()
            val requestLine = readHttpLine(rawIn) ?: return closeQuietly(client)
            val parts = requestLine.split(" ")
            if (parts.size < 2) { respondAndClose(client, 400, "text/plain", "bad request"); return }
            val method = parts[0]
            val requestTarget = parts[1]
            val path = requestTarget.substringBefore("?")
            val query = requestTarget.substringAfter("?", "")

            // Read headers we gate on; the rest are drained so a client that
            // also sent a body does not leave it framed on the socket.
            var guard: String? = null
            var origin: String? = null
            var contentLength = 0
            var signature: String? = null
            var timestamp: String? = null
            var nonce: String? = null
            var authorization: String? = null
            while (true) {
                val line = readHttpLine(rawIn) ?: break
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                when (line.substring(0, idx).trim().lowercase()) {
                    "x-peer-agent" -> guard = line.substring(idx + 1).trim()
                    "origin" -> origin = line.substring(idx + 1).trim()
                    "content-length" -> contentLength = line.substring(idx + 1).trim().toIntOrNull() ?: 0
                    "x-signature" -> signature = line.substring(idx + 1).trim()
                    "x-timestamp" -> timestamp = line.substring(idx + 1).trim()
                    "x-nonce" -> nonce = line.substring(idx + 1).trim()
                    "authorization" -> authorization = line.substring(idx + 1).trim()
                }
            }

            // Browser defence, per the class doc. Order: cheap method check,
            // then Origin (a cross-site form/fetch always sends it), then the
            // required non-simple header (an <img>/<form> cannot set it, and a
            // cross-origin fetch that does triggers a preflight we fail here).
            if (method != "GET" && method != "POST") {
                respondAndClose(client, 405, "text/plain", "method not allowed")
                return
            }
            if (origin != null) {
                respondAndClose(client, 403, "text/plain", "forbidden")
                return
            }
            if (guard != "1") {
                respondAndClose(client, 403, "text/plain", "forbidden")
                return
            }

            when {
                method == "GET" && path == "/events" -> handleSse(client)
                method == "GET" && path == "/status" -> respondAndClose(client, 200, "application/json", sink.statusJson())
                method == "GET" && path == "/art" -> {
                    val art = sink.artJpeg()
                    if (art != null) respondBytesAndClose(client, "image/jpeg", art)
                    else respondAndClose(client, 404, "text/plain", "no art")
                }
                method == "GET" && path == "/adb-port" -> {
                    val p = adb?.port()
                    if (p != null) respondAndClose(client, 200, "text/plain", p.toString())
                    else respondAndClose(client, 404, "text/plain", "wireless debugging off")
                }
                method == "POST" && path == "/adb/enable" -> handleAdbEnable(client)
                method == "POST" && path == "/adb/release" -> {
                    adb?.release()
                    respondAndClose(client, 200, "text/plain", "ok")
                }
                method == "POST" && path == "/command/play" -> { sink.play(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/pause" -> { sink.pause(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/next" -> { sink.next(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/prev" -> { sink.prev(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/seek-fwd" -> { sink.seekForward(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/seek-back" -> { sink.seekBackward(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/seek-to" -> handleSeekTo(client, query)
                method == "POST" && path == "/command/volume-up" -> { sink.volumeUp(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "POST" && path == "/command/volume-down" -> { sink.volumeDown(); respondAndClose(client, 200, "text/plain", "ok") }
                method == "GET" && path == "/privileged/diagnostics" ->
                    handlePrivileged(client, "GET", path, query, signature, timestamp, nonce, ByteArray(0)) { q ->
                        val pkg = queryParam(q, "pkg") ?: return@handlePrivileged 400 to "missing pkg"
                        val r = HelperBridge.enqueueAndWait("DIAG", pkg, ByteArray(0))
                        (if (r.ok) 200 else 502) to r.message
                    }
                method == "POST" && path == "/privileged/install" -> {
                    if (contentLength <= 0 || contentLength > 200 * 1024 * 1024) {
                        respondAndClose(client, 400, "text/plain", "bad or missing content-length")
                    } else {
                        val body = readExact(rawIn, contentLength)
                        // Fire-and-forget, not enqueueAndWait: installing
                        // peeragent's own package kills and restarts this
                        // process partway through pm install, which would
                        // tear down the very response thread trying to
                        // deliver a synchronous result - confirmed live (the
                        // install lands fine; only the reply never arrives).
                        // Caller confirms via a follow-up /privileged/diagnostics
                        // call (lastUpdateTime), same convention used
                        // elsewhere in this project to verify a silent install.
                        handlePrivileged(client, "POST", path, query, signature, timestamp, nonce, body) { q ->
                            val pkg = queryParam(q, "pkg") ?: return@handlePrivileged 400 to "missing pkg"
                            val id = HelperBridge.enqueueAsync("INSTALL", pkg, body)
                            if (id != null) 202 to "accepted, request id=$id - confirm via /privileged/diagnostics"
                            else 503 to "another privileged request is already in flight"
                        }
                    }
                }
                // Loopback-only, shared-secret-gated (see HelperBridge's class
                // doc for why not uid-checked): the privileged helper polls
                // this instead of peeragent connecting out to it.
                method == "GET" && path == "/helper/poll" -> handleHelperPoll(client, authorization)
                method == "POST" && path == "/helper/result" -> {
                    val len = contentLength.coerceAtMost(1_000_000)
                    val resultBody = if (len > 0) String(readExact(rawIn, len), StandardCharsets.UTF_8) else ""
                    handleHelperResult(client, query, authorization, resultBody)
                }
                else -> respondAndClose(client, 404, "text/plain", "not found")
            }
        } catch (t: Throwable) {
            log("handleClient failed: ${t.javaClass.name}: ${t.message}")
            closeQuietly(client)
        }
    }

    // Shared gate for both privileged-relay endpoints: Ed25519 signature
    // (host3-only, layered on top of WireGuard's peer trust) + a live check
    // that WireGuard is actually up right now, not just that the packet's
    // source address happens to look like it came through the tunnel.
    // Loopback ONLY, never 10.10.0.0/24 - this is purely local IPC to the
    // privileged helper, not something host3 or any other peer should ever
    // reach. sourceAllowed() already permits both; narrowed further here.
    private fun helperAuthorized(client: Socket, authorization: String?): Boolean {
        if (client.inetAddress?.isLoopbackAddress != true) {
            log("helper endpoint: rejected non-loopback source ${client.inetAddress?.hostAddress}")
            return false
        }
        return authorization == "Bearer ${HelperBridge.SHARED_SECRET}"
    }

    private fun handleHelperPoll(client: Socket, authorization: String?) {
        if (!helperAuthorized(client, authorization)) {
            respondAndClose(client, 403, "text/plain", "forbidden")
            return
        }
        val pending = HelperBridge.poll()
        if (pending == null) {
            respondAndClose(client, 204, "text/plain", "")
            return
        }
        // id \n action \n pkg \n <raw body bytes>
        val header = "${pending.id}\n${pending.action}\n${pending.pkg}\n".toByteArray(StandardCharsets.UTF_8)
        respondBytesAndClose(client, "application/octet-stream", header + pending.body)
    }

    private fun handleHelperResult(client: Socket, query: String, authorization: String?, body: String) {
        if (!helperAuthorized(client, authorization)) {
            respondAndClose(client, 403, "text/plain", "forbidden")
            return
        }
        val id = queryParam(query, "id")?.toLongOrNull()
        val ok = queryParam(query, "ok") == "1"
        if (id == null) {
            respondAndClose(client, 400, "text/plain", "missing id")
            return
        }
        val accepted = HelperBridge.submitResult(id, ok, body)
        respondAndClose(client, if (accepted) 200 else 404, "text/plain", if (accepted) "ok" else "no such pending request")
    }

    private fun handlePrivileged(
        client: Socket,
        method: String,
        path: String,
        query: String,
        signature: String?,
        timestamp: String?,
        nonce: String?,
        body: ByteArray,
        action: (String) -> Pair<Int, String>,
    ) {
        if (wireGuardActive?.invoke() != true) {
            log("privileged: rejected, WireGuard not active")
            respondAndClose(client, 503, "text/plain", "wireguard not active")
            return
        }
        if (signature == null || timestamp == null || nonce == null) {
            respondAndClose(client, 401, "text/plain", "missing signature headers")
            return
        }
        val ts = timestamp.toLongOrNull()
        if (ts == null) {
            respondAndClose(client, 401, "text/plain", "bad timestamp")
            return
        }
        val rejection = Ed25519Verify.verify(method, path, ts, nonce, body, signature)
        if (rejection != null) {
            log("privileged: rejected: $rejection")
            respondAndClose(client, 401, "text/plain", rejection)
            return
        }
        val (code, message) = action(query)
        respondAndClose(client, code, "text/plain", message)
    }

    private fun queryParam(query: String, name: String): String? =
        query.split("&")
            .firstOrNull { it.startsWith("$name=") }
            ?.removePrefix("$name=")
            ?.let { java.net.URLDecoder.decode(it, "UTF-8") }
            ?.takeIf { it.isNotEmpty() }

    private fun readHttpLine(input: InputStream): String? {
        val sb = StringBuilder()
        var any = false
        while (true) {
            val c = input.read()
            if (c == -1) return if (any) sb.toString() else null
            any = true
            if (c == '\n'.code) {
                if (sb.isNotEmpty() && sb.last() == '\r') sb.setLength(sb.length - 1)
                return sb.toString()
            }
            sb.append(c.toChar())
            if (sb.length > 8192) return sb.toString()
        }
    }

    private fun readExact(input: InputStream, length: Int): ByteArray {
        val buf = ByteArray(length)
        var off = 0
        while (off < length) {
            val n = input.read(buf, off, length - off)
            if (n < 0) throw IOException("body ended early, $off/$length bytes")
            off += n
        }
        return buf
    }

    private fun handleAdbEnable(client: Socket) {
        if (adb == null) { respondAndClose(client, 404, "text/plain", "not available"); return }
        try {
            val p = adb.acquire()
            if (p != null) respondAndClose(client, 200, "text/plain", p.toString())
            else respondAndClose(client, 503, "text/plain", "no port after enabling")
        } catch (e: SecurityException) {
            respondAndClose(client, 500, "text/plain", "WRITE_SECURE_SETTINGS not granted")
        }
    }

    private fun handleSeekTo(client: Socket, query: String) {
        // "ms=" + digits only. peer-agent's forward_query used to pre-validate
        // this; there is no other caller now, so it is validated only here.
        val ms = query.split("&")
            .firstOrNull { it.startsWith("ms=") }
            ?.removePrefix("ms=")
            ?.takeIf { it.isNotEmpty() && it.all(Char::isDigit) }
            ?.toLongOrNull()
        if (ms == null) {
            respondAndClose(client, 400, "text/plain", "bad or missing ms")
            return
        }
        sink.seekTo(ms)
        respondAndClose(client, 200, "text/plain", "ok")
    }

    private fun handleSse(client: Socket) {
        client.soTimeout = 0
        val os = client.getOutputStream()
        val headerText = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/event-stream\r\n" +
            "Cache-Control: no-cache\r\n" +
            "Connection: keep-alive\r\n\r\n"
        os.write(headerText.toByteArray(StandardCharsets.UTF_8))
        os.flush()
        sseClients.add(os)
    }

    private fun respondBytesAndClose(client: Socket, contentType: String, bytes: ByteArray) {
        try {
            val header = "HTTP/1.1 200 OK\r\nContent-Type: $contentType\r\n" +
                "Content-Length: ${bytes.size}\r\nConnection: close\r\n\r\n"
            val os = client.getOutputStream()
            os.write(header.toByteArray(StandardCharsets.UTF_8))
            os.write(bytes)
            os.flush()
        } catch (_: IOException) {
        } finally {
            closeQuietly(client)
        }
    }

    private fun respondAndClose(client: Socket, code: Int, contentType: String, body: String) {
        try {
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            val statusText = when (code) {
                200 -> "OK"
                400 -> "Bad Request"
                403 -> "Forbidden"
                404 -> "Not Found"
                500 -> "Internal Server Error"
                503 -> "Service Unavailable"
                405 -> "Method Not Allowed"
                else -> "Error"
            }
            val header = "HTTP/1.1 $code $statusText\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${bytes.size}\r\n" +
                "Connection: close\r\n\r\n"
            val os = client.getOutputStream()
            os.write(header.toByteArray(StandardCharsets.UTF_8))
            os.write(bytes)
            os.flush()
        } catch (_: IOException) {
        } finally {
            closeQuietly(client)
        }
    }

    private fun closeQuietly(client: Socket) {
        try { client.close() } catch (_: IOException) {}
    }
}
