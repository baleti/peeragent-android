package dev.local.peeragent

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks the port of this phone's own Wireless debugging (adbd TLS) listener.
 * The port changes every time Wireless debugging is toggled or the phone
 * reboots, and an app cannot read it from system properties, but adbd
 * advertises it over mDNS as `_adb-tls-connect._tcp` - the same trick Shizuku
 * uses. Kept current from a long-lived discovery so a request never waits.
 */
class AdbPortFinder(context: Context, private val log: (String) -> Unit) {
    private val nsd = context.getSystemService(NsdManager::class.java)
    private val ports = ConcurrentHashMap<String, Int>()   // service name -> port
    @Volatile private var started = false

    private val listener = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(serviceType: String) = log("adb mdns: discovery started")
        override fun onDiscoveryStopped(serviceType: String) = log("adb mdns: discovery stopped")
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = log("adb mdns: start failed $errorCode")
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = log("adb mdns: stop failed $errorCode")

        override fun onServiceFound(info: NsdServiceInfo) {
            @Suppress("DEPRECATION")
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(i: NsdServiceInfo, errorCode: Int) = log("adb mdns: resolve failed $errorCode")
                override fun onServiceResolved(i: NsdServiceInfo) {
                    ports[i.serviceName] = i.port
                    log("adb mdns: ${i.serviceName} -> ${i.port}")
                }
            })
        }

        override fun onServiceLost(info: NsdServiceInfo) {
            ports.remove(info.serviceName)
            log("adb mdns: lost ${info.serviceName}")
        }
    }

    @Synchronized
    fun start() {
        if (started) return
        started = true
        nsd.discoverServices("_adb-tls-connect._tcp", NsdManager.PROTOCOL_DNS_SD, listener)
    }

    @Synchronized
    fun stop() {
        if (!started) return
        started = false
        try { nsd.stopServiceDiscovery(listener) } catch (_: Exception) {}
        ports.clear()
    }

    /** Current Wireless debugging port, or null if it is off / not seen yet. */
    fun port(): Int? = ports.values.firstOrNull()
}
