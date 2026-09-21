package dev.local.peeragent

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager

/**
 * A handful of device/app facts reachable through plain public Android
 * APIs -- covers what this whole session's adb usage actually queried
 * (accessibility service state, SDK version, whether a package is
 * installed and its version) without needing adb/root/READ_LOGS at all.
 * Asked for explicitly 2026-09-21 ("run diagnostics... instead of
 * forcing adb"). Deliberately narrow -- this is not a general "run any
 * shell command" replacement, just the specific things actually used.
 */
object Diagnostics {
    fun json(context: Context, targetPackage: String?): String {
        val parts = mutableListOf<String>()
        parts.add("\"sdkInt\":${Build.VERSION.SDK_INT}")
        parts.add("\"release\":\"${esc(Build.VERSION.RELEASE)}\"")
        parts.add("\"model\":\"${esc(Build.MODEL)}\"")

        val am = context.getSystemService(AccessibilityManager::class.java)
        val enabled = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            ?.map { "${it.resolveInfo.serviceInfo.packageName}/${it.resolveInfo.serviceInfo.name}" }
            ?: emptyList()
        parts.add("\"enabledAccessibilityServices\":[${enabled.joinToString(",") { "\"${esc(it)}\"" }}]")

        if (!targetPackage.isNullOrBlank()) {
            val pm = context.packageManager
            try {
                val info = pm.getPackageInfo(targetPackage, 0)
                parts.add("\"targetInstalled\":true")
                parts.add("\"targetVersionName\":\"${esc(info.versionName)}\"")
                parts.add("\"targetVersionCode\":${info.longVersionCode}")
            } catch (_: PackageManager.NameNotFoundException) {
                parts.add("\"targetInstalled\":false")
            }
        }
        return "{${parts.joinToString(",")}}"
    }

    private fun esc(s: String?): String = (s ?: "").replace("\\", "\\\\").replace("\"", "\\\"")
}
