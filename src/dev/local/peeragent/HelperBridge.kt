package dev.local.peeragent

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * IPC to the "Peer App Debugger" privileged helper, reversed from the
 * original design: the helper (shell uid, launched via app_process) polls
 * *this* process's already-running BridgeHttpServer over loopback instead of
 * peeragent connecting out to a socket the helper owns. Two other designs
 * were tried and both failed on this specific device before landing here:
 *
 *   - A 127.0.0.1 TCP socket owned by the helper, with peeragent connecting
 *     to it: this device's "local network protection" feature (the
 *     ACCESS_LOCAL_NETWORK permission) mediates IP-layer loopback traffic
 *     from app UIDs, and the helper saw every caller as uid 2000/shell
 *     regardless of which app actually connected - the caller-uid check
 *     that whole design depended on was unusable.
 *   - A Unix-domain LocalServerSocket owned by the helper: SELinux denies a
 *     peer-to-peer AF_UNIX connect() across the shell/untrusted_app domain
 *     boundary outright (EACCES), confirmed live.
 *   - Writing request/response files to /data/local/tmp, shared by both
 *     processes: peeragent's untrusted_app uid cannot write there either
 *     (EACCES), confirmed live.
 *
 * This direction avoids all three: it is shell (not an app UID) making the
 * outbound loopback connection, and peeragent's own listening socket is
 * something it already fully controls. Caller identity for the two new
 * endpoints this exposes (/helper/poll, /helper/result) is *not* verified by
 * uid - the interim shared secret below is checked instead, since neither
 * procfs-uid nor SELinux-checked IPC turned out to be reachable from this
 * side of the boundary. This is a known-narrower interim MVP for Phase 1: it
 * should become a fresh per-session secret delivered over the same
 * Ed25519-signed bootstrap channel used for everything else, not a value
 * fixed at build time, before this goes beyond local testing.
 */
object HelperBridge {
    // MVP only - see class doc. SharedSecret.kt is gitignored (this repo is
    // public); matches the same value in
    // peer-app-debugger-android/helper/SharedSecret.java.
    val SHARED_SECRET = SharedSecret.VALUE

    private const val WAIT_TIMEOUT_MS = 60_000L
    private val nextId = AtomicLong(1)

    class PendingRequest(val id: Long, val action: String, val pkg: String, val body: ByteArray)

    private class InFlight(val request: PendingRequest) {
        val latch = CountDownLatch(1)
        @Volatile var resultOk: Boolean = false
        @Volatile var resultMessage: String = ""
    }

    @Volatile private var current: InFlight? = null
    private val lock = Any()

    class RelayResult(val ok: Boolean, val message: String)

    // INSTALL is fire-and-forget (see enqueueAsync's doc): when the target
    // package is peeragent's own, `pm install -r` kills and restarts this
    // whole process partway through, which tears down the very HTTP
    // response thread that would have delivered a synchronous result -
    // confirmed live (the install itself lands fine; only the response
    // never arrives). The caller is expected to confirm via a follow-up
    // DIAG call, same as this project's install-verification convention
    // elsewhere (checking lastUpdateTime via dumpsys).
    fun enqueueAsync(action: String, pkg: String, body: ByteArray): Long? {
        synchronized(lock) {
            if (current != null) return null
            val inFlight = InFlight(PendingRequest(nextId.getAndIncrement(), action, pkg, body))
            current = inFlight
            return inFlight.request.id
        }
    }

    /** Called from the privileged-relay HTTP handlers. One at a time. */
    fun enqueueAndWait(action: String, pkg: String, body: ByteArray): RelayResult {
        val inFlight: InFlight
        synchronized(lock) {
            if (current != null) return RelayResult(false, "another privileged request is already in flight")
            inFlight = InFlight(PendingRequest(nextId.getAndIncrement(), action, pkg, body))
            current = inFlight
        }
        try {
            val delivered = inFlight.latch.await(WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            if (!delivered) return RelayResult(false, "timed out waiting for helper (is it running and polling?)")
            return RelayResult(inFlight.resultOk, inFlight.resultMessage)
        } finally {
            synchronized(lock) { if (current === inFlight) current = null }
        }
    }

    /** Called from GET /helper/poll. Returns null if nothing pending. */
    fun poll(): PendingRequest? = current?.request

    /**
     * Called from POST /helper/result. Clears `current` itself (not just
     * enqueueAndWait's finally block) since enqueueAsync has no waiter to do
     * that cleanup - without this, a fire-and-forget INSTALL would leave
     * `current` permanently set and block every request after it.
     */
    fun submitResult(id: Long, ok: Boolean, message: String): Boolean {
        val inFlight = current
        if (inFlight == null || inFlight.request.id != id) return false
        synchronized(lock) { if (current === inFlight) current = null }
        inFlight.resultOk = ok
        inFlight.resultMessage = message
        inFlight.latch.countDown()
        return true
    }
}
