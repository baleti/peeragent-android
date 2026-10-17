package dev.local.peeragent

import android.os.FileObserver
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue

/**
 * Two-way mirror of [root] with host3's ~/share/pixel6, event driven in both
 * directions and deliberately stateless (see server/share-sync-daemon.py, the
 * other half):
 *
 *   - FileObserver on every directory under [root] pushes each local change
 *     to host3's daemon ([hostAddr]) as it happens.
 *   - host3 pushes its own changes to this app's BridgeHttpServer, which
 *     applies them through [putFile]/[deleteFile] below.
 *   - A catch-up pass every [RECONCILE_MS] pushes files host3 lacks or has an
 *     older copy of (covers events lost while off the tunnel). It never
 *     deletes: deletions travel only as live events.
 *
 * Changes applied from host3 are remembered for [ECHO_MS] so the observer
 * does not bounce them straight back. Conflicts are out of scope for now:
 * the newer mtime wins and the other copy is overwritten.
 */
class ShareSync(
    val root: File,
    private val hostAddr: String,
    private val log: (String) -> Unit,
) {
    companion object {
        const val PARTIAL = ".part-sync"
        const val ECHO_MS = 10_000L
        const val RECONCILE_MS = 60_000L
        private const val DELETED = -1L
        private val MASK = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or
            FileObserver.MOVED_FROM or FileObserver.DELETE or FileObserver.CREATE
    }

    private class Applied(val size: Long, val mtime: Long, val expiry: Long)

    private val applied = ConcurrentHashMap<String, Applied>()
    private val outbox = LinkedBlockingQueue<Pair<String, String>>()
    private val observers = HashMap<String, FileObserver>()
    @Volatile private var running = false

    @Volatile var lastPushOk = 0L
        private set

    fun start() {
        running = true
        root.mkdirs()
        addTree(root, announce = false)
        daemon { pusher() }
        daemon { reconciler() }
    }

    fun stop() {
        running = false
        synchronized(observers) {
            observers.values.forEach { it.stopWatching() }
            observers.clear()
        }
    }

    private fun daemon(body: () -> Unit) = Thread {
        try { body() } catch (t: Throwable) { log("share-sync thread died: ${t.javaClass.name}: ${t.message}") }
    }.apply { isDaemon = true }.start()

    // ------------------------------------------------------------ local side

    private fun rel(f: File) = f.relativeTo(root).path

    private fun addTree(top: File, announce: Boolean) {
        top.walkTopDown().forEach { f ->
            if (f.isDirectory) watchDir(f)
            else if (announce && !f.name.endsWith(PARTIAL)) outbox.put("put" to rel(f))
        }
    }

    private fun watchDir(dir: File) {
        synchronized(observers) {
            if (!running || observers.containsKey(dir.path)) return
            val obs = object : FileObserver(dir, MASK) {
                override fun onEvent(event: Int, path: String?) {
                    if (path == null || path.endsWith(PARTIAL)) return
                    val f = File(dir, path)
                    try {
                        when {
                            event and (CLOSE_WRITE or MOVED_TO or CREATE) != 0 ->
                                if (f.isDirectory) addTree(f, announce = true)
                                else if (event and CREATE == 0) outbox.put("put" to rel(f))
                            event and (DELETE or MOVED_FROM) != 0 -> outbox.put("del" to rel(f))
                        }
                    } catch (t: Throwable) {
                        log("share-sync observer: ${t.javaClass.simpleName}: ${t.message}")
                    }
                }
            }
            obs.startWatching()
            observers[dir.path] = obs
        }
    }

    // --------------------------------------------- applying host3's changes

    private fun resolve(rel: String): File? {
        val f = File(root, rel).canonicalFile
        return if (f.path.startsWith(root.canonicalPath + File.separator)) f else null
    }

    private fun mark(rel: String, size: Long, mtime: Long) {
        applied[rel] = Applied(size, mtime, System.currentTimeMillis() + ECHO_MS)
    }

    private fun isEcho(rel: String, size: Long, mtime: Long): Boolean {
        val a = applied[rel] ?: return false
        return a.expiry >= System.currentTimeMillis() && a.size == size && a.mtime == mtime
    }

    fun manifestJson(): String {
        val files = JSONObject()
        root.walkTopDown().filter { it.isFile && !it.name.endsWith(PARTIAL) }.forEach {
            files.put(rel(it), org.json.JSONArray().put(it.length()).put(it.lastModified() / 1000))
        }
        return JSONObject().put("files", files).toString()
    }

    fun openFile(rel: String): File? = resolve(rel)?.takeIf { it.isFile }

    fun putFile(rel: String, body: InputStream, length: Long, mtimeSec: Long?): Boolean {
        val dest = resolve(rel) ?: return false
        if (dest.name.endsWith(PARTIAL)) return false
        dest.parentFile?.mkdirs()
        val tmp = File(dest.path + PARTIAL)
        var left = length
        tmp.outputStream().use { out ->
            val buf = ByteArray(64 * 1024)
            while (left > 0) {
                val n = body.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                if (n < 0) break
                out.write(buf, 0, n)
                left -= n
            }
        }
        if (left > 0) { tmp.delete(); return false }
        if (mtimeSec != null) tmp.setLastModified(mtimeSec * 1000)
        mark(rel, length, tmp.lastModified() / 1000)
        if (dest.exists()) dest.delete()
        return tmp.renameTo(dest)
    }

    fun deleteFile(rel: String): Boolean {
        val f = resolve(rel)?.takeIf { it.isFile } ?: return false
        mark(rel, DELETED, 0)
        val ok = f.delete()
        var d = f.parentFile
        while (d != null && d != root.canonicalFile && d.delete()) d = d.parentFile
        return ok
    }

    // --------------------------------------------------------- push to host3

    private fun url(path: String) = URL("http://$hostAddr$path")

    private fun encode(rel: String) =
        rel.split(File.separator).joinToString("/") { URLEncoder.encode(it, "UTF-8").replace("+", "%20") }

    private fun call(method: String, path: String, body: File? = null): Int {
        val c = url(path).openConnection() as HttpURLConnection
        try {
            c.requestMethod = method
            c.connectTimeout = 5_000
            c.readTimeout = 20_000
            c.setRequestProperty("X-Share-Sync", "1")
            if (body != null) {
                c.doOutput = true
                c.setFixedLengthStreamingMode(body.length())
                c.setRequestProperty("X-Mtime", (body.lastModified() / 1000).toString())
                body.inputStream().use { i -> c.outputStream.use { o -> i.copyTo(o) } }
            }
            return c.responseCode
        } finally {
            c.disconnect()
        }
    }

    private fun pushFile(rel: String) {
        val f = File(root, rel)
        if (!f.isFile || isEcho(rel, f.length(), f.lastModified() / 1000)) return
        val code = call("PUT", "/file/" + encode(rel), f)
        if (code == 200) lastPushOk = System.currentTimeMillis()
        log("share-sync push $rel: $code")
    }

    private fun pushDelete(rel: String) {
        val a = applied[rel]
        if (a != null && a.size == DELETED && a.expiry >= System.currentTimeMillis()) return
        log("share-sync push delete $rel: ${call("DELETE", "/file/" + encode(rel))}")
    }

    private fun pusher() {
        while (running) {
            val (op, rel) = outbox.take()
            try {
                if (op == "put") pushFile(rel) else pushDelete(rel)
            } catch (e: Exception) {
                log("share-sync push $op $rel failed (${e.javaClass.simpleName}); next catch-up retries")
            }
        }
    }

    private fun reconcile() {
        val c = url("/manifest").openConnection() as HttpURLConnection
        val remote = try {
            c.setRequestProperty("X-Share-Sync", "1")
            c.connectTimeout = 5_000
            c.readTimeout = 20_000
            if (c.responseCode != 200) return
            JSONObject(c.inputStream.bufferedReader().readText()).getJSONObject("files")
        } finally {
            c.disconnect()
        }
        root.walkTopDown().filter { it.isFile && !it.name.endsWith(PARTIAL) }.forEach { f ->
            val rel = rel(f)
            val size = f.length()
            val mtime = f.lastModified() / 1000
            val r = remote.optJSONArray(rel)
            if (r == null || (r.getLong(1) < mtime && !(r.getLong(0) == size && r.getLong(1) == mtime))) {
                outbox.put("put" to rel)
            }
        }
    }

    private fun reconciler() {
        while (running) {
            try { reconcile() } catch (e: Exception) { log("share-sync catch-up: host3 unreachable (${e.javaClass.simpleName})") }
            try { Thread.sleep(RECONCILE_MS) } catch (_: InterruptedException) { return }
        }
    }
}
