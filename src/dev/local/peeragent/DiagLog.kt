package dev.local.peeragent

import android.content.ContentUris
import android.content.ContentValues
import android.content.Context
import android.os.Environment
import android.provider.MediaStore

/**
 * Shared diagnostic sink, written via MediaStore into the public Downloads
 * collection (readable from Termux) rather than getExternalFilesDir (which
 * this device's scoped-storage FUSE layer hides from other apps even with
 * "All files access" granted) or logcat (binder calls to system services are
 * refused for non-shell app UIDs on this device entirely).
 */
object DiagLog {
    private const val NAME = "peeragent-diag.log"
    private val buffer = StringBuilder()

    // Fire-and-forget: the MediaStore round-trip is itself suspected of
    // hanging (not throwing) on this device's binder policy, same as
    // startForeground() does. A synchronous call here would risk blocking
    // whatever thread logs a diagnostic - including the main thread during
    // onCreate() - so every write dispatches onto its own throwaway thread.
    fun write(ctx: Context, msg: String) {
        val appCtx = ctx.applicationContext
        Thread {
            writeBlocking(appCtx, msg)
        }.apply { isDaemon = true }.start()
    }

    @Synchronized
    private fun writeBlocking(ctx: Context, msg: String) {
        buffer.append("${System.currentTimeMillis()} $msg\n")
        try {
            val resolver = ctx.contentResolver
            var uri: android.net.Uri? = null
            resolver.query(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                arrayOf(MediaStore.MediaColumns._ID),
                "${MediaStore.MediaColumns.DISPLAY_NAME}=?",
                arrayOf(NAME),
                null,
            )?.use { c ->
                if (c.moveToFirst()) {
                    uri = ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI, c.getLong(0))
                }
            }
            if (uri == null) {
                val values = ContentValues().apply {
                    put(MediaStore.MediaColumns.DISPLAY_NAME, NAME)
                    put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                    put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                }
                uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            }
            uri?.let { u ->
                resolver.openOutputStream(u, "wt")?.use { os ->
                    os.write(buffer.toString().toByteArray())
                }
            }
        } catch (_: Exception) {
        }
    }
}
