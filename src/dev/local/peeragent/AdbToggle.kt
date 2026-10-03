package dev.local.peeragent

import android.content.Context
import android.provider.Settings
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

/**
 * Lends out Wireless debugging for a short window: [acquire] turns it on if it
 * was off and returns the port; [release] turns it off again, but only if
 * [acquire] was what turned it on. Left alone by us if it was already on.
 *
 * Writing `adb_wifi_enabled` needs WRITE_SECURE_SETTINGS, which an app cannot
 * request - grant it once from a paired host:
 *   adb shell pm grant dev.local.peeragent android.permission.WRITE_SECURE_SETTINGS
 *
 * If the caller never releases (host died mid-dance), a timer switches it off
 * anyway, and the "we turned it on" flag is persisted so a restarted service
 * still cleans up.
 */
class AdbToggle(
    private val context: Context,
    private val finder: AdbPortFinder,
    private val log: (String) -> Unit,
) {
    private companion object {
        const val KEY = "adb_wifi_enabled"
        const val MAX_ON_SECONDS = 90L
        const val PORT_WAIT_MS = 10_000L
    }

    private val prefs = context.getSharedPreferences("adb_toggle", Context.MODE_PRIVATE)
    private val timer = Executors.newSingleThreadScheduledExecutor()
    private var pendingOff: ScheduledFuture<*>? = null

    init {
        if (prefs.getBoolean("by_us", false)) schedule()   // left on by a previous run
    }

    private fun isOn() = Settings.Global.getInt(context.contentResolver, KEY, 0) == 1
    private fun put(on: Boolean) = Settings.Global.putInt(context.contentResolver, KEY, if (on) 1 else 0)

    private fun schedule() {
        pendingOff?.cancel(false)
        pendingOff = timer.schedule({ release() }, MAX_ON_SECONDS, TimeUnit.SECONDS)
    }

    fun port(): Int? = finder.port()

    /** Port of Wireless debugging, turning it on first if needed. Throws on missing permission. */
    fun acquire(): Int? {
        synchronized(this) {
            if (!isOn()) {
                finder.restart()
                put(true)
                prefs.edit().putBoolean("by_us", true).apply()
                log("adb toggle: turned Wireless debugging on")
            }
            if (prefs.getBoolean("by_us", false)) schedule()
        }
        val deadline = System.currentTimeMillis() + PORT_WAIT_MS
        var restarted = false
        while (System.currentTimeMillis() < deadline) {
            finder.port()?.let { return it }
            // Nothing after 3 s: the advert may have been swallowed, look again.
            if (!restarted && System.currentTimeMillis() > deadline - PORT_WAIT_MS + 3_000) {
                finder.restart(); restarted = true
            }
            Thread.sleep(100)
        }
        return null
    }

    /** Turn Wireless debugging back off if [acquire] turned it on. */
    @Synchronized
    fun release(): Boolean {
        pendingOff?.cancel(false)
        pendingOff = null
        if (!prefs.getBoolean("by_us", false)) return false
        put(false)
        prefs.edit().putBoolean("by_us", false).apply()
        log("adb toggle: turned Wireless debugging back off")
        return true
    }
}
