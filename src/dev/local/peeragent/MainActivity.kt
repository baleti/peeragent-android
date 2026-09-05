package dev.local.peeragent

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private val notifPermRequestCode = 1001

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Declared in the manifest but that alone does nothing on API 33+ -
        // POST_NOTIFICATIONS is a runtime (dangerous) permission and dumpsys
        // confirmed it was never actually granted since nothing ever called
        // requestPermissions() for it.
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), notifPermRequestCode)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 80, 40, 40)
        }

        val info = TextView(this).apply {
            text = "PeerAgent companion\n\n" +
                "Port: ${BridgeForegroundService.PORT} (0.0.0.0)\n" +
                "Reachable only from 10.10.0.0/24 (WireGuard) or loopback, and " +
                "only with the X-Peer-Agent: 1 header. Serves the media-* " +
                "commands directly; peer-agent no longer sits in front."
            textSize = 14f
            setTextIsSelectable(true)
        }
        root.addView(info)

        val notifBtn = Button(this).apply {
            text = "Open notification access settings"
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            }
        }
        root.addView(notifBtn)

        val startBtn = Button(this).apply {
            text = "Start bridge service"
            setOnClickListener {
                DiagLog.write(this@MainActivity, "MainActivity: Start bridge service tapped")
                try {
                    startForegroundService(Intent(this@MainActivity, BridgeForegroundService::class.java))
                    DiagLog.write(this@MainActivity, "MainActivity: startForegroundService() returned OK")
                    Toast.makeText(this@MainActivity, "start requested", Toast.LENGTH_SHORT).show()
                } catch (e: Throwable) {
                    DiagLog.write(this@MainActivity, "MainActivity: startForegroundService threw ${e.javaClass.name}: ${e.message}")
                    Log.e("PeerAgentCompanion", "startForegroundService threw: ${e.message}")
                    Toast.makeText(this@MainActivity, "failed: ${e.javaClass.simpleName}", Toast.LENGTH_LONG).show()
                }
            }
        }
        root.addView(startBtn)

        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == notifPermRequestCode) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            Toast.makeText(this, "notifications permission: ${if (granted) "granted" else "denied"}", Toast.LENGTH_SHORT).show()
        }
    }
}
