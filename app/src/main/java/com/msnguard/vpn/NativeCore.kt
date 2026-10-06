package com.msnguard.vpn

object NativeCore {
    init {
        System.loadLibrary("aether")
        System.loadLibrary("aether_jni")
    }

    /**
     * The tunnel addresses the UI shows. Aether 2.3.0 does not return them
     * from the engine (it owns no TUN), so they come from the config the
     * VpnService builds and hands to [prepare].
     */
    var configIpv4: String = "172.16.0.2"
    var configIpv6: String = "2606:4700:110:88b9::2"
    internal set

    data class TunnelAddresses(
        val ipv4: String,
        val ipv6: String,
        val gatewayProxy: String = "",
        val organization: String = "",
    )

    fun prepare(config: String): TunnelAddresses {
        // Aether 2.3.0 has no prepare step: the engine loads or provisions the
        // identity inside aether_core_start and scans inside the job. The
        // addresses the UI shows come from the config the service builds, not
        // from the engine, so this is now informational only.
        nativePrepare(config)
        return TunnelAddresses(
            configIpv4,
            configIpv6,
            gatewayProxy = "",
            organization = "",
        )
    }

    fun requestEmailCode(team: String, email: String) {
    }

    fun confirmEmailCode(code: String): String {
        nativeConfirmEmailCode(code)
        return ""
    }

    fun start(config: String, tunFd: Int): Int = nativeStart(config, tunFd)

    /**
     * Start the core with no Android TUN, exposing a local SOCKS5 listener.
     *
     * The `tun_fd`-less path in main.rs builds the userspace netstack and runs
     * `socks::serve` instead of `tun::bridge`. Psiphon-over-WARP needs exactly
     * that: WARP carries the traffic, Psiphon dials out through this listener as
     * its upstream proxy, and tun2socks owns the device's TUN on the other side.
     *
     * Blocks until the tunnel exits, like [start] — call it on a worker thread.
     */
    fun startProxy(config: String): Int = nativeStartProxy(config)
    fun stop(): Int = nativeStop()
    fun isRunning(): Boolean = nativeIsRunning()
    fun isReady(): Boolean = nativeIsReady()
    fun lastError(): String = nativeLastError()
    fun lastLog(): String = nativeLastLog()
    fun attach(service: MsnGuardVpnService) = nativeAttach(service)
    fun detach() = nativeDetach()

    interface CoreCallback {
        fun onEvent(json: String)
    }

    /**
     * Writes one `AETHER_*` variable into the process environment the dlopen'd
     * engine reads. Used by [CoreConfig.applyEnv] before a start.
     */
    fun setEnv(key: String, value: String) = nativeSetEnv(key, value)

    @JvmStatic private external fun nativePrepare(config: String): Int
    @JvmStatic private external fun nativeSetEnv(key: String, value: String)
    @JvmStatic private external fun nativeLastResult(): String
    @JvmStatic private external fun nativeRequestEmailCode(team: String, email: String): Int
    @JvmStatic private external fun nativeConfirmEmailCode(code: String): Int
    @JvmStatic private external fun nativeStart(config: String, tunFd: Int): Int
    @JvmStatic private external fun nativeStartProxy(config: String): Int
    @JvmStatic private external fun nativeStop(): Int
    @JvmStatic private external fun nativeIsRunning(): Boolean
    @JvmStatic private external fun nativeIsReady(): Boolean
    @JvmStatic private external fun nativeLastError(): String
    @JvmStatic private external fun nativeLastLog(): String
    @JvmStatic private external fun nativeAttach(service: MsnGuardVpnService)
    @JvmStatic private external fun nativeDetach()
}
