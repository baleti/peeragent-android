package dev.local.peeragent

import java.io.ByteArrayOutputStream
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
    private val installer: AppInstaller? = null,
    private val diagContext: android.content.Context? = null,
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

            // Raw byte-based line reading, NOT a BufferedReader -- a
            // BufferedReader/InputStreamReader decodes+buffers ahead of
            // whatever readLine() actually consumes, which would silently
            // swallow/corrupt the start of a binary body (see /app/install
            // below, the first route here that ever needs one). Reading
            // one byte at a time guarantees the stream sits at EXACTLY the
            // first body byte once the blank line after headers is seen.
            val rawInput = client.getInputStream()
            val requestLine = readLineRaw(rawInput) ?: return closeQuietly(client)
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
            while (true) {
                val line = readLineRaw(rawInput) ?: break
                if (line.isEmpty()) break
                val idx = line.indexOf(':')
                if (idx <= 0) continue
                when (line.substring(0, idx).trim().lowercase()) {
                    "x-peer-agent" -> guard = line.substring(idx + 1).trim()
                    "origin" -> origin = line.substring(idx + 1).trim()
                    "content-length" -> contentLength = line.substring(idx + 1).trim().toIntOrNull() ?: 0
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
                method == "POST" && path == "/app/install" -> handleAppInstall(client, rawInput, contentLength)
                method == "GET" && path == "/diag" -> {
                    val ctx = diagContext
                    if (ctx == null) {
                        respondAndClose(client, 404, "text/plain", "not available")
                    } else {
                        val targetPackage = query.split("&")
                            .firstOrNull { it.startsWith("package=") }
                            ?.removePrefix("package=")
                        respondAndClose(client, 200, "application/json", Diagnostics.json(ctx, targetPackage))
                    }
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
                else -> respondAndClose(client, 404, "text/plain", "not found")
            }
        } catch (t: Throwable) {
            log("handleClient failed: ${t.javaClass.name}: ${t.message}")
            closeQuietly(client)
        }
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

    // Body cap matches the largest APK any of this project's apps has
    // built to so far, with real headroom -- large enough for any of
    // these hand-built (no dependency bloat) apps, small enough that a
    // malformed/hostile Content-Length can't be used to make this thread
    // allocate something absurd.
    private val MAX_APK_BYTES = 64 * 1024 * 1024

    private fun handleAppInstall(client: Socket, rawInput: InputStream, contentLength: Int) {
        if (installer == null) { respondAndClose(client, 404, "text/plain", "not available"); return }
        if (contentLength <= 0 || contentLength > MAX_APK_BYTES) {
            respondAndClose(client, 400, "text/plain", "bad or missing Content-Length")
            return
        }
        log("app/install: reading $contentLength bytes")
        val apkBytes = try {
            readBodyRaw(rawInput, contentLength)
        } catch (e: IOException) {
            log("app/install: body read failed: ${e.message}")
            respondAndClose(client, 400, "text/plain", "body read failed: ${e.message}")
            return
        }
        log("app/install: body read ok (${apkBytes.size} bytes), committing session")
        val result = installer.install(apkBytes)
        log("app/install: result=$result")
        val code = if (result == "installed") 200 else 500
        respondAndClose(client, code, "text/plain", result)
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

    // One byte at a time, deliberately -- see acceptLoop's call site doc
    // for why this replaces the earlier BufferedReader (over-buffering
    // would eat into a binary body that follows the headers).
    private fun readLineRaw(input: InputStream): String? {
        val buf = ByteArrayOutputStream()
        while (true) {
            val b = input.read()
            if (b == -1) return if (buf.size() == 0) null else buf.toString("UTF-8")
            if (b == '\n'.code) {
                val bytes = buf.toByteArray()
                val end = if (bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) bytes.size - 1 else bytes.size
                return String(bytes, 0, end, StandardCharsets.UTF_8)
            }
            buf.write(b)
        }
    }

    private fun readBodyRaw(input: InputStream, length: Int): ByteArray {
        val out = ByteArray(length)
        var off = 0
        while (off < length) {
            val n = input.read(out, off, length - off)
            if (n == -1) throw IOException("connection closed after $off/$length bytes")
            off += n
        }
        return out
    }
}
