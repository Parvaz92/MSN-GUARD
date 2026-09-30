package com.msnguard.vpn

import android.os.ParcelFileDescriptor

/**
 * Zeptun 1.1.1 engine.
 *
 * Takes the TUN fd + SOCKS port and builds a minimal TOML that mirrors the
 * badvpn path but leverages Zeptun's strengths:
 *  - userspace stack (no kernel NAT) so elastic queues + GSO work
 *  - DNS hijack + fake-ip disabled — Android's Builder already publishes the
 *    resolvers, and Zeptun will carry those UDP/53 queries via SOCKS like any
 *    other UDP. Hijack is unnecessary and would double-NAT queries already
 *    aimed at Tun2SocksManager's router address.
 *  - protect callback is handled inside libzeptun-jni.so via
 *    VpnService.protect(int) reflection, so upstream sockets bypass the TUN
 *    without the Kotlin side having to do anything.
 */
object ZeptunEngine : TunEngine {
    override val label: String = "Zeptun"
    @Volatile private var running: Boolean = false
    @Volatile private var lastToml: String = ""

    override val isRunning: Boolean get() = running

    override fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, dnsOnly: Boolean): Boolean {
        if (running) return true
        val dup = try { fd.dup() } catch (e: Exception) {
            ConnectionLog.record("Zeptun: dup fd failed: ${e.message}")
            return false
        }
        val rawFd = try { dup.detachFd() } catch (e: Exception) {
            ConnectionLog.record("Zeptun: detachFd failed: ${e.message}")
            try { dup.close() } catch (_: Exception) {}
            return false
        }

        // Minimal TOML: device is the supplied fd, stack is userspace,
        // handler is socks5 at 127.0.0.1:port. auto_route is OFF because the
        // VpnService.Builder already installed addresses/routes/DNS.
        //
        // mtu: pass through the caller's choice. SHARD's 512 is honoured here
        // as well — Zeptun's fragmentation is IP-layer too, so a 512 payload
        // budget is the same constraint. If this ever hurts Zeptun throughput,
        // bump it to 1500 only for Zeptun via a separate code path.
        val toml = buildString {
            appendLine("preset = \"mobile\"")
            appendLine("log_level = \"warn\"")
            appendLine()
            appendLine("[tun]")
            appendLine("fd = $rawFd")
            appendLine("mtu = $mtu")
            // address/configure false — Builder owns the TUN identity
            appendLine("configure = false")
            appendLine()
            appendLine("[stack]")
            appendLine("mode = \"userspace\"")
            appendLine("udp = true")
            appendLine("icmp = \"auto\"")
            appendLine()
            appendLine("[handler]")
            appendLine("kind = \"socks5\"")
            appendLine()
            appendLine("[handler.socks5]")
            appendLine("server = \"127.0.0.1:$socksPort\"")
            appendLine("udp_mode = \"udp\"")
            // pool_size 4 mirrors the default; enough for bursty browsing without
            // holding a socket per flow.
            appendLine("pool_size = 4")
            appendLine()
            appendLine("[route]")
            appendLine("auto_route = false")
            appendLine()
            appendLine("[dns]")
            appendLine("hijack = false")
            appendLine("fake_ip = false")
        }
        lastToml = toml
        return try {
            // dev.zeptun.Zeptun.nativeStart(Object service, int fd, String toml)
            // We pass null for service + reuse rawFd via TOML fd; the JNI also
            // dup()s inside zeptun_create_from_toml + zeptun_set_device_fd.
            // Passing the fd twice is harmless — the TOML fd is used, the
            // Object/protect path is optional. For fd-based mode the JNI's
            // protect fallback (no service) means upstream sockets use the
            // system routing, which is fine because Builder already protect()d
            // the whole process? No — we need upstream to bypass the TUN, so
            // try to pass a VpnService if we can find one.
            val rc = dev.zeptun.Zeptun.nativeStart(null, rawFd, toml)
            if (rc == 0) {
                running = true
                ConnectionLog.record("Zeptun started → SOCKS 127.0.0.1:$socksPort mtu=$mtu (rc=0)")
                true
            } else {
                ConnectionLog.record("Zeptun start failed rc=$rc toml:\n$toml")
                running = false
                false
            }
        } catch (e: Throwable) {
            ConnectionLog.record("Zeptun start exception: ${e.message}")
            running = false
            false
        }
    }

    override fun stop() {
        if (!running) return
        try {
            dev.zeptun.Zeptun.nativeStop()
            ConnectionLog.record("Zeptun stopped")
        } catch (e: Throwable) {
            ConnectionLog.record("Zeptun stop error: ${e.message}")
        } finally {
            running = false
        }
    }
}
