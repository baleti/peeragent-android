package dev.local.peeragent

import android.content.Intent
import android.service.notification.NotificationListenerService

class BridgeNotificationListener : NotificationListenerService() {

    override fun onListenerConnected() {
        super.onListenerConnected()
        startForegroundService(Intent(this, BridgeForegroundService::class.java))
    }
}
