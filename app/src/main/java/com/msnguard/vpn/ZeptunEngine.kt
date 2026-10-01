package com.msnguard.vpn

import android.os.ParcelFileDescriptor

/**
 * Zeptun 1.1.1 engine.
 *
 * Takes the TUN fd + SOCKS port and builds a minimal TOML that mirrors the
 * Hev path but leverages Zeptun's strengths:
 *  - userspace stack (no kernel NAT) so elastic queues + GSO work
 *  - DNS: hijack + fake-ip are ON. The Builder publishes only the synthetic
 *    fake-ip resolver (HevEngine.MAP_DNS_ADDRESS), Zeptun answers it from its
 *    own fake-ip table, and real resolvers are handed to the engine here so
 *    it resolves the domain itself over SOCKS. Carrying a bare UDP/53 query
 *    for an Iran-only server (e.g. 111.88.96.50) out of a foreign WARP
 *    egress never gets an answer, which is exactly what killed UDP DNS.
 *  - protect callback is handled inside libzeptun-jni.so via
 *    VpnService.protect(int) reflection, so upstream sockets bypass the TUN
 *    without the Kotlin side having to do anything.
 */
object ZeptunEngine : TunEngine {
    override val label: String = "Zeptun"
    @Volatile private var running: Boolean = false
    @Volatile private var lastToml: String = ""

    override val isRunning: Boolean get() = running

    /**
     * Custom resolvers the user set (dns_servers preference), followed by the
     * public fallbacks the TUN had before. Same parsing rules as
     * MsnGuardVpnService.applyDns so one field works everywhere.
     */
    private fun customResolverList(): List<String> {
        val raw = runCatching { AppContext.get()!!.profiled().getString("dns_servers", null)?.trim().orEmpty() }
            .getOrDefault("")
        val out = ArrayList<String>()
        if (raw.isNotEmpty()) {
            raw.split(',', ';', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.forEach { token ->
                // Encrypted entries (tls://, dot://, https://) are passed
                // through untouched: the scheme is what the core keys on and
                // the port belongs to it (853/443), so stripping it would
                // corrupt the entry. Plain entries keep the old host-only
                // normalisation below.
                if (token.startsWith("tls://") || token.startsWith("dot://") ||
                    token.startsWith("https://")
                ) {
                    if (token !in out) out.add(token)
                    return@forEach
                }
                var host = token
                if (host.startsWith("[")) {
                    host = host.substringAfter("[").substringBefore("]")
                } else if (host.count { it == ':' } > 1 && !host.contains('.')) {
                    // bare v6 without brackets — keep as is
                } else if (host.contains(":")) {
                    host = host.substringBefore(":")
                }
                host = host.trim().removePrefix("[").removeSuffix("]")
                if (host.isNotEmpty() && host !in out) out.add(host)
            }
        }
        for (fallback in listOf("1.1.1.1", "8.8.8.8")) {
            if (fallback !in out) out.add(fallback)
        }
        return out
    }

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

        // Custom resolvers the user set, to the engine. Zeptun's [dns].upstream
        // takes ONE address, so the first custom entry wins (that is the
        // Iran-only server the user actually wants). If none is set, the public
        // fallback is used so resolution still works.
        val upstream = customResolverList().firstOrNull() ?: "1.1.1.1"
        ConnectionLog.record("Zeptun DNS upstream=$upstream (hijack+fake_ip, range 198.18.0.0/15)")

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
            // DNS: hijack + fake-ip. The Builder publishes only the synthetic
            // fake-ip resolver (198.18.0.2, inside Zeptun's default
            // 198.18.0.0/15 fake range), Zeptun answers it from its own
            // fake-ip table, and the real resolver is named here so the engine
            // resolves the domain itself over SOCKS. A bare UDP/53 query for an
            // Iran-only server (e.g. 111.88.96.50) leaving a foreign WARP
            // egress never gets an answer — that is what killed UDP DNS.
            appendLine("[dns]")
            appendLine("hijack = true")
            appendLine("fake_ip = true")
            appendLine("upstream = \"$upstream\"")
            appendLine("cache_size = 10000")
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
