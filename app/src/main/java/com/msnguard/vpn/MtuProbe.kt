package com.msnguard.vpn

import android.util.Log
import java.util.concurrent.TimeUnit

/**
 * Finds the largest packet the carrier link can carry, then subtracts the
 * per-method framing so the MTU field becomes a measurement.
 *
 * Why the OUTER path: the app excludes its own package from the TUN
 * (addDisallowedApplication), so a probe started from here always rides the
 * carrier link even while a tunnel is up — it measures the same link the
 * tunnel's outer packets ride. The tunnel need not be connected. The
 * overheads below were measured on a live 1500-byte path (connect the
 * method, ping through it from a shell which IS NOT excluded, find the
 * exact size that stops arriving). WireGuard proves it: 1500-1440 = 60 =
 * 20 IPv4 + 8 UDP + 32 WireGuard on paper, and the wire agrees.
 *
 * Methods that never put an inner packet on the wire (tun2socks) have no
 * PMTU to measure — bigger is strictly better, so they answer 1500 without
 * a probe. SHARD is the exception: its pool sits behind a WebSocket leg
 * that drops >512, so its ceiling is 512 even though it is also local.
 */
object MtuProbe {

    private const val TAG = "MtuProbe"

    /** IPv4 + ICMP echo header. `ping -s N` sends N bytes on top of this. */
    private const val ICMP_OVERHEAD = 28

    /** Methods whose TUN never puts a packet on the wire. */
    val LOCAL_TERMINATION = setOf(
        MtuConfig.Method.PSIPHON,
        MtuConfig.Method.TOR,
    )

    /**
     * Bytes each method adds to an inner packet, measured on the wire.
     * MASQUE 196 = QUIC inside WARP-tunnel-inside-MASQUE (two encap layers);
     * WOW/WARP-on-WARP 280 = three layers. WireGuard 60 = 20+8+32 exact.
     */
    private val OVERHEAD = mapOf(
        MtuConfig.Method.MASQUE to 196,
        MtuConfig.Method.WIREGUARD to 60,
        MtuConfig.Method.WOW to 280,
    )

    private fun targetFor(method: MtuConfig.Method): String = when (method) {
        MtuConfig.Method.MASQUE,
        MtuConfig.Method.WIREGUARD,
        MtuConfig.Method.WOW -> "162.159.192.1"
        else -> "1.1.1.1"
    }

    data class Result(
        val method: MtuConfig.Method,
        val outerPathMtu: Int?,
        val inner: Int?,
        val localTermination: Boolean,
        val probes: Int,
    )

    /**
     * Blocking measurement — call off the main thread.
     * [onProgress] is called with each MTU tried so the UI can show the search.
     */
    fun measure(
        method: MtuConfig.Method,
        onProgress: (Int) -> Unit = {},
    ): Result {
        // SHARD: WebSocket ceiling, not a PMTU — never probe.
        if (method == MtuConfig.Method.SHARD) {
            return Result(method, null, MtuConfig.DEFAULT_SHARD, true, 0)
        }
        if (method in LOCAL_TERMINATION) {
            return Result(method, null, MtuConfig.MAX_MTU, true, 0)
        }

        val host = targetFor(method)
        var probes = 0
        fun fits(mtu: Int): Boolean {
            probes++
            onProgress(mtu)
            return ping(host, mtu - ICMP_OVERHEAD)
        }

        if (!fits(MtuConfig.MIN_MTU)) {
            return Result(method, null, null, false, probes)
        }

        var lo = MtuConfig.MIN_MTU
        var hi = MtuConfig.MAX_MTU
        if (fits(hi)) {
            lo = hi
        } else {
            while (lo + 1 < hi) {
                val mid = (lo + hi) / 2
                if (fits(mid)) lo = mid else hi = mid
            }
        }

        var best = lo
        while (best > MtuConfig.MIN_MTU && !fits(best)) best -= 4
        if (best < MtuConfig.MAX_MTU && fits(best + 1)) {
            while (best < MtuConfig.MAX_MTU && fits(best + 1)) best++
        }

        val inner = (best - (OVERHEAD[method] ?: 0)).coerceIn(MtuConfig.MIN_MTU, MtuConfig.MAX_MTU)
        Log.i(TAG, "${method.title}: outer=$best inner=$inner after $probes probes to $host")
        return Result(method, best, inner, false, probes)
    }

    private fun ping(host: String, payload: Int): Boolean = try {
        val p = ProcessBuilder(
            "/system/bin/ping", "-n", "-c", "1", "-W", "2", "-M", "do", "-s", payload.toString(), host
        ).redirectErrorStream(true).start()
        val done = p.waitFor(4, TimeUnit.SECONDS)
        if (!done) {
            p.destroyForcibly()
            false
        } else {
            p.exitValue() == 0
        }
    } catch (e: Exception) {
        Log.w(TAG, "probe failed at $payload: ${e.message}")
        false
    }
}
