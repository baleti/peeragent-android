package dev.local.peeragent

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

/**
 * Extra defense-in-depth for the privileged-relay endpoints specifically:
 * BridgeHttpServer's source-IP check (10.10.0.0/24 + loopback) already means
 * a request could only structurally have arrived over the WireGuard tunnel or
 * from this device itself, but that's a property of the packet's source
 * address, not a live check that the tunnel itself is actually up right now.
 * This asks ConnectivityManager directly whether an active VPN-transport
 * network currently exists, so a stale route or spoofed-adjacent state can't
 * let a privileged request through if WireGuard itself has actually dropped.
 */
object WireGuardCheck {
    // Checked against every known network, not just getActiveNetwork(): a
    // split-tunnel WireGuard config (only 10.10.0.0/24 routed through it)
    // never becomes the *default* route, so activeNetwork() alone would
    // wrongly report "no VPN" even with the tunnel fully up.
    fun isActive(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return false
            cm.allNetworks.any { net ->
                val caps = cm.getNetworkCapabilities(net)
                caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        } catch (_: Exception) {
            false
        }
    }
}
