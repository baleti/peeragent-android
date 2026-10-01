package dev.local.peeragent

import java.security.SecureRandom
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
 * uid - a shared secret is checked instead, since neither procfs-uid nor
 * SELinux-checked IPC turned out to be reachable from this side of the
 * boundary. Fresh per bootstrap session (startNewSession(), called from
 * POST /helper/new-session), not a value fixed at build time.
 */
object HelperBridge {
    // Was a value fixed at build time (SharedSecret.kt, gitignored - this
    // repo is public); now generated fresh by startNewSession() each time
    // the tile app self-bootstraps, passed to the helper as an
    // app_process launch argument. SharedSecret.VALUE survives only as the
    // fallback a manually-launched helper (adb shell, no launch arg - this
    // project's own testing workflow) still authenticates with; a warning
    // logs on the helper side whenever that fallback is actually used.
    @Volatile var currentSecret: String = SharedSecret.VALUE
        private set

    /**
     * Starts a fresh bootstrap session: a new random secret, with any
     * already-connected helper (necessarily authenticated under the *old*
     * secret) told to stop first and given a moment to actually do so.
     * Without this ordering, swapping the secret out from under a live
     * helper would orphan it - its poll/result calls would start failing
     * auth immediately, with no way left to deliver it a STOP using the
     * new secret it doesn't know.
     */
    fun startNewSession(): String {
        if (helperConnected()) {
            requestLocalStop()
            val deadline = System.currentTimeMillis() + 5_000
            while (helperConnected() && System.currentTimeMillis() < deadline) {
                Thread.sleep(200)
            }
        }
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val secret = bytes.joinToString("") { "%02x".format(it) }
        currentSecret = secret
        return secret
    }

    private const val WAIT_TIMEOUT_MS = 60_000L
    // A fire-and-forget request (enqueueAsync: INSTALL, local-stop) has no
    // caller waiting to clear `current` on its own timeout the way
    // enqueueAndWait's finally block does - if the helper dies or never
    // polls it up, the single in-flight slot would otherwise stay wedged
    // forever, blocking every request after it (found live: a STOP queued
    // right as the helper was exiting left `current` stuck, and the next
    // DIAG call failed immediately with "already in flight" instead of even
    // attempting to run). Anything older than this is treated as abandoned.
    private const val STALE_MS = 90_000L
    private val nextId = AtomicLong(1)

    class PendingRequest(val id: Long, val action: String, val pkg: String, val body: ByteArray)

    private class InFlight(val request: PendingRequest) {
        val latch = CountDownLatch(1)
        val createdAt = System.currentTimeMillis()
        @Volatile var resultOk: Boolean = false
        @Volatile var resultMessage: String = ""
    }

    private fun isStale(inFlight: InFlight) = System.currentTimeMillis() - inFlight.createdAt > STALE_MS

    @Volatile private var current: InFlight? = null
    private val lock = Any()

    class RelayResult(val ok: Boolean, val message: String)

    // Deliberately reachable without Ed25519/WireGuard-active (see
    // BridgeHttpServer's /helper/local-stop, loopback-only): stopping is
    // conservative - it can only end the privileged process early, never
    // trigger a privileged action - and "the user can stop it themselves at
    // any time, without needing host3" was an explicit requirement. Returns
    // false only if a different request is already in flight.
    fun requestLocalStop(): Boolean = enqueueAsync("STOP", "", ByteArray(0)) != null

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
            val existing = current
            if (existing != null && !isStale(existing)) return null
            val inFlight = InFlight(PendingRequest(nextId.getAndIncrement(), action, pkg, body))
            current = inFlight
            return inFlight.request.id
        }
    }

    /** Called from the privileged-relay HTTP handlers. One at a time. */
    fun enqueueAndWait(action: String, pkg: String, body: ByteArray): RelayResult {
        val inFlight: InFlight
        synchronized(lock) {
            val existing = current
            if (existing != null && !isStale(existing)) return RelayResult(false, "another privileged request is already in flight")
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

    // Updated on every real poll from the helper (~1.5s interval - see
    // PrivilegedHelper.java's POLL_INTERVAL_MS), so the tile app can show
    // whether host3 has actually finished bootstrapping it yet instead of a
    // static "waiting" message that never changes once it's actually
    // running (found live: exactly this staleness, with the tile
    // correctly armed and the helper already running and handling real
    // requests).
    @Volatile private var lastPollAt: Long = 0
    private const val LIVENESS_WINDOW_MS = 5_000L

    fun helperConnected(): Boolean = System.currentTimeMillis() - lastPollAt < LIVENESS_WINDOW_MS

    /**
     * Called from GET /helper/poll. Returns null if nothing pending.
     *
     * A stale request is discarded here, not just refused as a *new*
     * enqueue - found live: a STOP queued by a disarm tap while no helper
     * was running sat in `current` indefinitely (nothing ever polled it up
     * to clear it), then got served, unwanted, to the *next* freshly-
     * bootstrapped helper's very first poll - which dutifully obeyed a
     * minutes-old command and exited immediately instead of starting up.
     */
    fun poll(): PendingRequest? {
        lastPollAt = System.currentTimeMillis()
        synchronized(lock) {
            val existing = current
            if (existing != null && isStale(existing)) {
                current = null
                return null
            }
            return existing?.request
        }
    }

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
