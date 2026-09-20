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

    /** The live discovery; events from any earlier (stopped) one are ignored. */
    @Volatile private var current: NsdManager.DiscoveryListener? = null

    private fun newListener() = object : NsdManager.DiscoveryListener {
        private fun live() = current === this
        override fun onDiscoveryStarted(serviceType: String) = log("adb mdns: discovery started")
        override fun onDiscoveryStopped(serviceType: String) = log("adb mdns: discovery stopped")
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) = log("adb mdns: start failed $errorCode")
        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) = log("adb mdns: stop failed $errorCode")

        override fun onServiceFound(info: NsdServiceInfo) {
            if (!live()) return
            @Suppress("DEPRECATION")
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(i: NsdServiceInfo, errorCode: Int) = log("adb mdns: resolve failed $errorCode")
                override fun onServiceResolved(i: NsdServiceInfo) {
                    if (!live()) return
                    ports[i.serviceName] = i.port
                    log("adb mdns: ${i.serviceName} -> ${i.port}")
                }
            })
        }

        override fun onServiceLost(info: NsdServiceInfo) {
            if (!live()) return
            ports.remove(info.serviceName)
            log("adb mdns: lost ${info.serviceName}")
        }
    }

    @Synchronized
    fun start() {
        if (started) return
        started = true
        val l = newListener()
        current = l
        nsd.discoverServices("_adb-tls-connect._tcp", NsdManager.PROTOCOL_DNS_SD, l)
    }

    @Synchronized
    fun stop() {
        if (!started) return
        started = false
        val l = current
        current = null
        try { if (l != null) nsd.stopServiceDiscovery(l) } catch (_: Exception) {}
        ports.clear()
    }

    /**
     * Forget everything and rediscover. adbd re-advertises under the *same*
     * service name with a new port on every toggle, so a late "lost" for the old
     * registration can erase the new port; a fresh discovery replays what is
     * really there.
     */
    fun restart() {
        stop()
        start()
    }

    /** Current Wireless debugging port, or null if it is off / not seen yet. */
    fun port(): Int? = ports.values.firstOrNull { listening(it) }

    private fun listening(port: Int): Boolean = try {
        java.net.Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 300); true }
    } catch (_: Exception) { false }
}
