package com.msnguard.vpn

import android.os.ParcelFileDescriptor

/** Thin wrapper so TunEngineManager can delegate to the existing badvpn path. */
object LegacyEngine : TunEngine {
    override val label: String = "Legacy"
    override val isRunning: Boolean get() = Tun2SocksManager.isRunning
    override fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, dnsOnly: Boolean): Boolean =
        Tun2SocksManager.start(fd, socksPort, dnsOnlyUdpgw = dnsOnly, mtu = mtu)
    override fun stop() = Tun2SocksManager.stop()
}
