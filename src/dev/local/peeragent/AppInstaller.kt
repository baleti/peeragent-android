package dev.local.peeragent

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Notification
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Silent-as-possible app install/update over the WireGuard bridge --
 * "add ability to update the app... instead of forcing adb and
 * potentially weakening the security posture of this phone" (asked for
 * explicitly 2026-09-21, after confirming adb-over-WireGuard's on-demand
 * path (AdbToggle) can't be trusted to work on an untrusted network
 * without a live test proving it, and this app's own bridge already does
 * -- it's plain WireGuard transport, nothing tied to Android's
 * Wireless-Debugging/Developer-Options machinery at all).
 *
 * Uses PackageInstaller's session API -- the same mechanism the Play
 * Store itself uses -- not `pm install` (needs shell/adb privilege this
 * app doesn't have, and never will without root). A system confirmation
 * dialog still appears per install UNLESS this app has been set as the
 * target package's trusted installer, a one-time `adb shell pm
 * set-installer <pkg> dev.local.peeragent` done once while adb access is
 * available (see README) -- there is no API-level way around that
 * confirmation from a plain app UID otherwise, by design (Android's own
 * defense against a compromised app silently installing malware).
 */
class AppInstaller(private val context: Context) {
    companion object {
        private const val ACTION_INSTALL_STATUS = "dev.local.peeragent.INSTALL_STATUS"
        private const val CHANNEL_ID = "peeragent_install"
        private const val NOTIF_ID_BASE = 9000
    }

    private val latches = ConcurrentHashMap<Int, CountDownLatch>()
    private val results = ConcurrentHashMap<Int, Pair<Int, String?>>() // sessionId -> (status, message)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            val sessionId = intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID, -1)
            val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
            Log.i("PeerAgentCompanion", "AppInstaller: onReceive session=$sessionId status=$status")
            if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                // Not resolved yet -- this app isn't the trusted installer
                // for this package, so the system needs a visible tap to
                // confirm. Calling startActivity() directly here does NOT
                // throw but silently never brings the confirm UI to the
                // foreground -- confirmed live 2026-09-21: a background
                // activity launch from a plain BroadcastReceiver callback
                // is blocked by Android's own background-activity-launch
                // restrictions regardless of this app running a foreground
                // service elsewhere. A notification's PendingIntent, tapped
                // by the user, is a genuine user-initiated launch and isn't
                // subject to that restriction -- also just better UX than a
                // dialog stealing focus from whatever's on screen. A second
                // broadcast follows once the user taps through it (or the
                // session times out).
                @Suppress("DEPRECATION")
                val confirmIntent = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                if (confirmIntent != null) {
                    confirmIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    postConfirmNotification(sessionId, confirmIntent)
                    Log.i("PeerAgentCompanion", "AppInstaller: posted confirm notification for session=$sessionId")
                } else {
                    Log.e("PeerAgentCompanion", "AppInstaller: STATUS_PENDING_USER_ACTION with no EXTRA_INTENT")
                }
                return
            }
            val message = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
            results[sessionId] = status to message
            latches[sessionId]?.countDown()
            // Resolved (success or failure) -- clear the now-stale prompt
            // rather than leaving a dead notification around.
            context.getSystemService(NotificationManager::class.java).cancel(NOTIF_ID_BASE + sessionId)
        }
    }

    private fun postConfirmNotification(sessionId: Int, confirmIntent: Intent) {
        val nm = context.getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "App install confirmation", NotificationManager.IMPORTANCE_HIGH),
            )
        }
        val pendingIntent = PendingIntent.getActivity(
            context, sessionId, confirmIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL_ID)
            .setContentTitle("Install update")
            .setContentText("Tap to confirm installing the app sent over the bridge")
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()
        nm.notify(NOTIF_ID_BASE + sessionId, notification)
    }

    init {
        val filter = IntentFilter(ACTION_INSTALL_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
    }

    /** Installs/updates from raw APK bytes, blocking (up to [timeoutMs])
     * until the install actually resolves -- either silently (trusted
     * installer already set) or after a confirmation tap. Returns a
     * short human-readable result string, never throws. */
    fun install(apkBytes: ByteArray, timeoutMs: Long = 180_000): String {
        val pm = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        val sessionId = try {
            pm.createSession(params)
        } catch (e: Exception) {
            return "error creating session: ${e.javaClass.simpleName}: ${e.message}"
        }
        val session = pm.openSession(sessionId)
        return try {
            session.openWrite("apk", 0, apkBytes.size.toLong()).use { out ->
                out.write(apkBytes)
                session.fsync(out)
            }
            val latch = CountDownLatch(1)
            latches[sessionId] = latch
            val statusIntent = Intent(ACTION_INSTALL_STATUS).setPackage(context.packageName)
            val pendingIntent = PendingIntent.getBroadcast(
                context, sessionId, statusIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            session.commit(pendingIntent.intentSender)
            session.close()
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                "timed out waiting for install to resolve (may be sitting on a confirmation tap)"
            } else {
                val (status, message) = results.remove(sessionId) ?: (PackageInstaller.STATUS_FAILURE to "no result")
                if (status == PackageInstaller.STATUS_SUCCESS) "installed" else "failed: ${message ?: status}"
            }
        } catch (e: Exception) {
            try { session.abandon() } catch (_: Exception) {}
            "error: ${e.javaClass.simpleName}: ${e.message}"
        } finally {
            latches.remove(sessionId)
        }
    }
}
