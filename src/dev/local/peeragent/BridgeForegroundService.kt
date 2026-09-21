package dev.local.peeragent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.AudioManager
import android.media.MediaMetadata
import android.media.session.MediaController
import android.media.session.MediaSessionManager
import android.media.session.PlaybackState
import android.net.Uri
import android.os.IBinder
import android.util.Log
import java.io.ByteArrayOutputStream
import java.util.concurrent.CopyOnWriteArrayList

class BridgeForegroundService : Service(), CommandSink {

    companion object {
        const val TAG = "PeerAgentCompanion"
        const val CHANNEL_ID = "peeragent_status"
        const val NOTIF_ID = 1
        const val PORT = 8788
        const val SEEK_STEP_MS = 5000L
    }

    private lateinit var mediaSessionManager: MediaSessionManager
    private lateinit var listenerComponent: ComponentName
    private var httpServer: BridgeHttpServer? = null
    private var adbPortFinder: AdbPortFinder? = null
    private var adbToggle: AdbToggle? = null
    private val audioManager: AudioManager by lazy { getSystemService(AudioManager::class.java) }

    private val controllers = CopyOnWriteArrayList<MediaController>()
    @Volatile private var canonical: MediaController? = null
    private val callbacks = HashMap<MediaController, MediaController.Callback>()

    private val sessionsChangedListener =
        MediaSessionManager.OnActiveSessionsChangedListener { newControllers ->
            onSessionsChanged(newControllers ?: emptyList())
        }

    private fun diag(msg: String) = DiagLog.write(this, msg)

    override fun onCreate() {
        super.onCreate()
        // Nothing in here may be allowed to throw past this function: an
        // uncaught exception in onCreate() force-closes the whole app, and
        // there is no way to read this device's crash log to diagnose that
        // after the fact (pm/settings/dumpsys binder calls are refused for a
        // plain app UID). Degraded but running beats a crash we can't see.
        try {
            listenerComponent = ComponentName(this, BridgeNotificationListener::class.java)
            mediaSessionManager = getSystemService(MediaSessionManager::class.java)

            try {
                startForeground(
                    NOTIF_ID,
                    buildNotification("starting"),
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
                )
            } catch (e: Throwable) {
                diag("onCreate: startForeground threw ${e.javaClass.name}: ${e.message}")
                Log.e(TAG, "startForeground failed: ${e.message}")
            }

            try {
                mediaSessionManager.addOnActiveSessionsChangedListener(sessionsChangedListener, listenerComponent)
                onSessionsChanged(mediaSessionManager.getActiveSessions(listenerComponent))
            } catch (e: SecurityException) {
                diag("onCreate: media session listener SecurityException: ${e.message}")
                Log.e(TAG, "notification access not granted: ${e.message}")
            } catch (e: Exception) {
                diag("onCreate: media session listener threw ${e.javaClass.name}: ${e.message}")
                Log.e(TAG, "session listener setup failed: ${e.message}")
            }

            try {
                val adbLog = { msg: String -> Log.i(TAG, msg); diag(msg) }
                val finder = AdbPortFinder(this, adbLog).also { it.start() }
                adbPortFinder = finder
                adbToggle = AdbToggle(this, finder, adbLog)
                httpServer = BridgeHttpServer(PORT, this, { msg -> Log.i(TAG, msg) }, adbToggle)
                httpServer?.start()
            } catch (e: Throwable) {
                diag("onCreate: http server threw ${e.javaClass.name}: ${e.message}")
                Log.e(TAG, "http server start failed: ${e.message}")
            }
        } catch (t: Throwable) {
            diag("onCreate: TOP-LEVEL ${t.javaClass.name}: ${t.message}")
            Log.e(TAG, "onCreate top-level failure: ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    override fun onDestroy() {
        diag("onDestroy: called")
        try {
            mediaSessionManager.removeOnActiveSessionsChangedListener(sessionsChangedListener)
        } catch (_: Exception) {
        }
        for ((controller, cb) in callbacks) controller.unregisterCallback(cb)
        callbacks.clear()
        httpServer?.stop()
        adbPortFinder?.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    private fun onSessionsChanged(newControllers: List<MediaController>) {
        for ((controller, cb) in callbacks) {
            if (!newControllers.contains(controller)) controller.unregisterCallback(cb)
        }
        callbacks.keys.retainAll(newControllers.toSet())
        controllers.clear()
        controllers.addAll(newControllers)

        for (controller in newControllers) {
            if (!callbacks.containsKey(controller)) {
                val cb = object : MediaController.Callback() {
                    override fun onPlaybackStateChanged(state: PlaybackState?) {
                        canonical = controller
                        pushState()
                    }

                    override fun onMetadataChanged(metadata: MediaMetadata?) {
                        canonical = controller
                        pushState()
                    }

                    override fun onSessionDestroyed() {
                        controllers.remove(controller)
                        callbacks.remove(controller)
                        if (canonical == controller) canonical = controllers.firstOrNull()
                        pushState()
                    }
                }
                controller.registerCallback(cb)
                callbacks[controller] = cb
            }
        }

        if (canonical == null || !newControllers.contains(canonical)) {
            canonical = newControllers.firstOrNull()
        }
        pushState()
    }

    private fun pushState() {
        httpServer?.broadcast(statusJson())
        updateNotification()
    }

    private fun updateNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        val title = canonical?.metadata?.getString(MediaMetadata.METADATA_KEY_TITLE) ?: "idle"
        nm.notify(NOTIF_ID, buildNotification(title))
    }

    private fun buildNotification(status: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "PeerAgent companion status", NotificationManager.IMPORTANCE_LOW),
            )
        }
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("PeerAgent companion")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    private fun esc(s: String?): String {
        if (s == null) return ""
        val sb = StringBuilder()
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> {}
                c.code < 0x20 -> {}
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    // STREAM_MUSIC's current level as a 0.0-1.0 ratio - independent of
    // whether any app has an active MediaSession, since this is the same
    // system volume the hardware buttons control. Exposed so the desktop
    // bridge's MPRIS Volume property reflects the phone's real level
    // instead of a hardcoded constant.
    private fun volumeRatio(): Float {
        val max = audioManager.getStreamMaxVolume(AudioManager.STREAM_MUSIC)
        if (max <= 0) return 1f
        return audioManager.getStreamVolume(AudioManager.STREAM_MUSIC).toFloat() / max
    }

    override fun statusJson(): String {
        val c = canonical ?: return "{\"active\":false,\"volume\":${volumeRatio()}}"
        val md = c.metadata
        val title = md?.getString(MediaMetadata.METADATA_KEY_TITLE)
        val artist = md?.getString(MediaMetadata.METADATA_KEY_ARTIST)
        val album = md?.getString(MediaMetadata.METADATA_KEY_ALBUM)
        val duration = md?.getLong(MediaMetadata.METADATA_KEY_DURATION) ?: -1L
        val state = c.playbackState
        val stateStr = when (state?.state) {
            PlaybackState.STATE_PLAYING -> "playing"
            PlaybackState.STATE_PAUSED -> "paused"
            PlaybackState.STATE_STOPPED -> "stopped"
            PlaybackState.STATE_BUFFERING -> "buffering"
            else -> "unknown"
        }
        val position = state?.position ?: -1L
        val speed = state?.playbackSpeed ?: 1.0f
        val pkg = c.packageName ?: ""
        return "{\"active\":true,\"title\":\"${esc(title)}\",\"artist\":\"${esc(artist)}\",\"album\":\"${esc(album)}\"," +
            "\"state\":\"$stateStr\",\"position\":$position,\"duration\":$duration,\"speed\":$speed," +
            "\"volume\":${volumeRatio()},\"package\":\"${esc(pkg)}\",\"art\":${hasArt(md)}}"
    }

    // Cover art for the current track, for the desktop bridge's notifications
    // and MPRIS artUrl. Players hand it over as a Bitmap and/or a URI; take a
    // bitmap when there is one (nothing to fetch), else try to open the URI.
    // Not every player publishes any -- callers must cope with null.
    private val artBitmapKeys = arrayOf(
        MediaMetadata.METADATA_KEY_ALBUM_ART, MediaMetadata.METADATA_KEY_ART,
        MediaMetadata.METADATA_KEY_DISPLAY_ICON)
    private val artUriKeys = arrayOf(
        MediaMetadata.METADATA_KEY_ALBUM_ART_URI, MediaMetadata.METADATA_KEY_ART_URI,
        MediaMetadata.METADATA_KEY_DISPLAY_ICON_URI)

    private fun hasArt(md: MediaMetadata?): Boolean =
        md != null && (artBitmapKeys.any { md.getBitmap(it) != null } ||
            artUriKeys.any { !md.getString(it).isNullOrEmpty() })

    private fun loadUri(uriStr: String): Bitmap? = try {
        val uri = Uri.parse(uriStr)
        if (uri.scheme == "http" || uri.scheme == "https") {
            java.net.URL(uriStr).openStream().use { BitmapFactory.decodeStream(it) }
        } else {
            contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it) }
        }
    } catch (t: Throwable) {
        diag("art uri failed ($uriStr): ${t.javaClass.simpleName}: ${t.message}")
        null
    }

    override fun artJpeg(): ByteArray? {
        val md = canonical?.metadata ?: return null
        var bmp: Bitmap? = artBitmapKeys.firstNotNullOfOrNull { md.getBitmap(it) }
        if (bmp == null) {
            for (k in artUriKeys) {
                val u = md.getString(k)
                if (!u.isNullOrEmpty()) { bmp = loadUri(u); if (bmp != null) break }
            }
        }
        if (bmp == null) return null
        // 512px is plenty for a notification thumbnail / media panel and keeps
        // the transfer to a few tens of KB over the tunnel.
        val longest = maxOf(bmp.width, bmp.height)
        if (longest > 512) {
            val f = 512f / longest
            bmp = Bitmap.createScaledBitmap(bmp, (bmp.width * f).toInt().coerceAtLeast(1),
                (bmp.height * f).toInt().coerceAtLeast(1), true)
        }
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.JPEG, 85, out)
        return out.toByteArray()
    }

    override fun play() { canonical?.transportControls?.play() }
    override fun pause() { canonical?.transportControls?.pause() }
    override fun next() { canonical?.transportControls?.skipToNext() }
    override fun prev() { canonical?.transportControls?.skipToPrevious() }
    override fun seekForward() = seekBy(SEEK_STEP_MS)
    override fun seekBackward() = seekBy(-SEEK_STEP_MS)
    override fun volumeUp() =
        audioManager.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_RAISE, AudioManager.FLAG_SHOW_UI)
    override fun volumeDown() =
        audioManager.adjustStreamVolume(AudioManager.STREAM_MUSIC, AudioManager.ADJUST_LOWER, AudioManager.FLAG_SHOW_UI)
    override fun seekTo(positionMs: Long) {
        val c = canonical ?: return
        val duration = c.metadata?.getLong(MediaMetadata.METADATA_KEY_DURATION) ?: -1L
        var target = positionMs
        if (target < 0) target = 0
        if (duration > 0 && target > duration) target = duration
        c.transportControls.seekTo(target)
    }

    private fun seekBy(deltaMs: Long) {
        val c = canonical ?: return
        val pos = c.playbackState?.position ?: return
        val duration = c.metadata?.getLong(MediaMetadata.METADATA_KEY_DURATION) ?: -1L
        var target = pos + deltaMs
        if (target < 0) target = 0
        if (duration > 0 && target > duration) target = duration
        c.transportControls.seekTo(target)
    }
}
