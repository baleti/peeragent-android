package dev.local.peeragent

import android.accessibilityservice.AccessibilityService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Reads the Wireless debugging "Pair device with pairing code" dialog out of
 * com.android.settings (the code is shown nowhere else and no API exposes it),
 * so a host can fetch it from GET /adb/pairing instead of the user reading it
 * off the phone. Scoped to com.android.settings by the service config.
 *
 * While [armed] (set by POST /adb/pair-start) it also clicks through
 * Developer options > Wireless debugging > "Pair device with pairing code".
 * Navigation matches English UI strings.
 *
 * The service is enabled by the app itself via [ensureEnabled] (needs the
 * WRITE_SECURE_SETTINGS already granted for AdbToggle).
 */
class PairingCaptureService : AccessibilityService() {

    companion object {
        private const val FRESH_MS = 120_000L
        private val CODE = Regex("""\b(\d{6})\b""")
        private val HOSTPORT = Regex("""\b(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})\b""")

        @Volatile private var captured: Pair<String, String>? = null   // code, ip:port
        @Volatile private var capturedAt = 0L
        @Volatile private var armedUntil = 0L

        fun arm(seconds: Long) { armedUntil = System.currentTimeMillis() + seconds * 1000 }
        fun disarm() { armedUntil = 0L }
        private fun armed() = System.currentTimeMillis() < armedUntil

        /** "code ip:port" if a dialog was read in the last two minutes. */
        fun latest(): String? {
            val c = captured ?: return null
            if (System.currentTimeMillis() - capturedAt > FRESH_MS) return null
            return "${c.first} ${c.second}"
        }

        fun clear() { captured = null }

        fun ensureEnabled(context: Context) {
            val me = ComponentName(context, PairingCaptureService::class.java).flattenToString()
            val cr = context.contentResolver
            val cur = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            if (cur.split(':').contains(me)) return
            Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
                if (cur.isEmpty()) me else "$cur:$me")
            Settings.Secure.putInt(cr, Settings.Secure.ACCESSIBILITY_ENABLED, 1)
        }

        fun openDevOptions(context: Context) {
            context.startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            // A static screen emits no events, so drive navigation by timer too.
            if (armed()) step()
            handler.postDelayed(this, 700)
        }
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        handler.post(tick)
    }

    override fun onDestroy() {
        handler.removeCallbacks(tick)
        super.onDestroy()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) = step()

    private fun step() {
        val root = rootInActiveWindow
        if (root == null) { android.util.Log.i("PairCap", "step: no root"); return }
        android.util.Log.i("PairCap", "step: pkg=${root.packageName} armed=${armed()}")
        if (root.packageName != "com.android.settings") return
        try {
            val texts = ArrayList<String>()
            collect(root, texts)
            val joined = texts.joinToString("\n")

            if (joined.contains("pairing code", ignoreCase = true)) {
                val hp = HOSTPORT.find(joined)?.value
                val code = texts.firstNotNullOfOrNull { t ->
                    CODE.matchEntire(t.trim().replace(" ", ""))?.value
                }
                if (hp != null && code != null) {
                    captured = code to hp
                    capturedAt = System.currentTimeMillis()
                    return
                }
            }

            if (!armed()) return
            // Navigation: click the first matching row/button, one hop per event.
            for (label in listOf("Pair device with pairing code", "Wireless debugging")) {
                if (clickText(root, label)) return
            }
            // Developer options list: the row may be off-screen.
            val sc = scrollForward(root)
            android.util.Log.i("PairCap", "scroll -> $sc")
        } finally {
            root.recycle()
        }
    }

    private fun collect(n: AccessibilityNodeInfo, out: MutableList<String>) {
        n.text?.toString()?.takeIf { it.isNotBlank() }?.let(out::add)
        for (i in 0 until n.childCount) {
            val c = n.getChild(i) ?: continue
            collect(c, out)
            c.recycle()
        }
    }

    private fun clickText(root: AccessibilityNodeInfo, label: String): Boolean {
        for (n in root.findAccessibilityNodeInfosByText(label)) {
            if (!n.text.toString().equals(label, ignoreCase = true)) continue
            var t: AccessibilityNodeInfo? = n
            while (t != null && !t.isClickable) t = t.parent
            if (t != null && t.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true
        }
        return false
    }

    private fun scrollForward(root: AccessibilityNodeInfo): Boolean {
        fun find(n: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            // Deepest scrollable wins: the outer one is the collapsing-toolbar
            // ScrollView, the list that holds the rows is nested inside it.
            for (i in 0 until n.childCount) { n.getChild(i)?.let { find(it)?.let { r -> return r } } }
            return if (n.isScrollable) n else null
        }
        return find(root)?.performAction(AccessibilityNodeInfo.ACTION_SCROLL_FORWARD) ?: false
    }

    override fun onInterrupt() {}
}
