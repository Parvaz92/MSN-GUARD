package com.msnguard.vpn

import android.os.ParcelFileDescriptor
import java.io.File

/**
 * Hev-socks5-tunnel engine.
 *
 * Config is a YAML file, not a string: TProxyStartService(String path, int fd).
 * We write a minimal config under filesDir/hev/hev-<port>.yml and let Hev's
 * native thread own it. stop() is blocking (pthread_join), so it must be called
 * off the main thread — MsnGuardVpnService.stopTunnel already runs there.
 *
 * DNS: Hev's mapdns (198.18.0.2) is enabled. Android's Builder still publishes
 * custom resolvers (e.g. 111.88.96.50) as TUN DNS servers; Hev forwards those
 * UDP/53 queries via SOCKS, so Iran-only resolvers that are only reachable
 * through the tunnel will still answer. mapdns handles queries aimed at the
 * synthetic 198.18.0.2 address; everything else is plain SOCKS UDP.
 */
object HevEngine : TunEngine {
    override val label: String = "Hev"
    @Volatile private var lastConfigPath: String? = null

    override val isRunning: Boolean get() = try { hev.htproxy.TProxyService.TProxyIsRunning() } catch (_: Throwable) { false }

    override fun start(fd: ParcelFileDescriptor, socksPort: Int, mtu: Int, dnsOnly: Boolean): Boolean {
        if (isRunning) return true
        // Prefer AppContext; TunEngineManager already has a Context but the
        // interface does not carry it — keep this indirection so HevEngine
        // stays a pure TunEngine.
        val ctx = AppContext.get() ?: run {
            ConnectionLog.record("Hev: no AppContext, cannot write config")
            return false
        }
        val dup = try { fd.dup() } catch (e: Exception) {
            ConnectionLog.record("Hev: dup fd failed: ${e.message}")
            return false
        }
        val rawFd = try { dup.detachFd() } catch (e: Exception) {
            ConnectionLog.record("Hev: detachFd failed: ${e.message}")
            try { dup.close() } catch (_: Exception) {}
            return false
        }
        val dir = File(ctx.filesDir, "hev").apply { mkdirs() }
        val cfgFile = File(dir, "hev-$socksPort.yml")
        // Minimal YAML that matches hev's sample conf/main.yml:
        // tunnel { name, mtu, ipv4/ipv6, multi-queue off }
        // socks5 { address, port, udp, mark(0)=no fwmark }
        // misc { task-stack, connect-timeout etc — defaults OK }
        val addr = Tun2SocksManager.privateAddress
        val yaml = buildString {
            appendLine("tunnel:")
            appendLine("  name: tun0")
            appendLine("  mtu: $mtu")
            appendLine("  ipv4: ${addr.ipAddress}/8")
            // Hev requires an ipv6 or it defaults to fd00::1; keep it simple.
            appendLine("  ipv6: \"fd00::1/64\"")
            appendLine("  multi-queue: false")
            appendLine("socks5:")
            appendLine("  address: 127.0.0.1")
            appendLine("  port: $socksPort")
            // hev udp modes: tcp|udp — udp avoids an extra TCP leg for DNS
            appendLine("  udp: udp")
            // No fwmark: upstream sockets are already protect()ed by the
            // VpnService or by Zeptun's protect path. Hev's set_sock_mark
            // would only matter with a real mark value.
            appendLine("misc:")
            appendLine("  task-stack-size: 81920")
            appendLine("  connect-timeout: 5000")
            appendLine("  read-write-timeout: 60000")
            appendLine("  log-file: stderr")
            appendLine("  log-level: warn")
            appendLine("mapdns:")
            appendLine("  address: 198.18.0.2")
            appendLine("  port: 53")
            appendLine("  network: 100.64.0.0")
            appendLine("  netmask: 255.192.0.0")
            appendLine("  cache-size: 10000")
        }
        try {
            cfgFile.writeText(yaml)
        } catch (e: Exception) {
            ConnectionLog.record("Hev: write config failed: ${e.message}")
            return false
        }
        lastConfigPath = cfgFile.absolutePath
        return try {
            val ok = hev.htproxy.TProxyService.TProxyStartService(cfgFile.absolutePath, rawFd)
            if (ok) {
                ConnectionLog.record("Hev started → SOCKS 127.0.0.1:$socksPort mtu=$mtu")
            } else {
                ConnectionLog.record("Hev start returned false (check logcat hev)")
            }
            ok
        } catch (e: Throwable) {
            ConnectionLog.record("Hev start exception: ${e.message}")
            false
        }
    }

    override fun stop() {
        try {
            if (isRunning) {
                hev.htproxy.TProxyService.TProxyStopService()
                ConnectionLog.record("Hev stopped")
            }
        } catch (e: Throwable) {
            ConnectionLog.record("Hev stop error: ${e.message}")
        } finally {
            // Best-effort remove the ephemeral config so filesDir does not pile up.
            try { lastConfigPath?.let { File(it).delete() } } catch (_: Exception) {}
            lastConfigPath = null
        }
    }
}
