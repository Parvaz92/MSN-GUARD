package com.msnguard.vpn

import com.msnguard.vpn.ConnectionLog.record
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The loopback SOCKS5 front for the Hev/Zeptun WARP path when the user has
 * encrypted DNS and the engine cannot speak it itself.
 *
 * ## Why this front exists
 *
 * Hev and Zeptun hand the TUN to a SOCKS5 listener and point the engine at it,
 * and aether's own listener ([CoreConfig.SOCKS_PORT], 127.0.0.1:1819) is a plain
 * SOCKS proxy: it answers CONNECT and UDP ASSOCIATE and applies the routing
 * rules, but it does not resolve names, and its UDP ASSOCIATE carries only plain
 * UDP/53. A `tls://` or `https://` DNS entry therefore has nowhere to go, and
 * the TUN's resolver — a synthetic address nothing answers — dies. Every
 * name-based site fails while IP-only apps (Telegram) keep working. That
 * asymmetry is the field symptom.
 *
 * This class is the answer. It binds 127.0.0.1:[LISTEN_PORT] in front of
 * 127.0.0.1:1819, and the engine is pointed at it instead of at aether:
 *
 * ```
 *   TUN → Hev/Zeptun → SmartDnsFront:1827
 *      ├─ CONNECT <SMART_DNS_RESOLVER:53> → answered here (DoT/DoH lookup)
 *      ├─ CONNECT <anything else>         → relayed verbatim to aether 1819
 *      ├─ UDP ASSOCIATE, port 53          → answered here (NODATA for AAAA/HTTPS
 *      │                                     when the egress is v4-only)
 *      └─ UDP ASSOCIATE, everything else  → relayed verbatim to aether 1819
 * ```
 *
 * ## How this differs from [WarpUdpgwFront] and [ShardSocksFront]
 *
 * Those exist because badvpn's tun2socks speaks its own udpgw protocol for UDP
 * rather than SOCKS. This one does not implement udpgw at all: Hev and Zeptun
 * are full SOCKS5 clients and issue real CONNECT and UDP ASSOCIATE requests, so
 * this is a plain SOCKS5 server with a DNS policy bolted on. The wire handling
 * is simpler, and the interesting part is which flows get answered locally.
 *
 * ## Why AAAA and HTTPS get NODATA
 *
 * The WARP egress is IPv4-only (aether runs an IPv4-only netstack; see the
 * `spawn("198.18.0.1", "fc00::1")` calls in netstack.rs). A real AAAA answer
 * would hand the app a v6 address it cannot route, so it connects to a black
 * hole and stalls instead of falling back. HTTPS/SVCB (type 65) carries the
 * same v6 hints and ECH keys the egress cannot use.
 *
 * NODATA — an empty NOERROR reply — is what a real resolver returns when it has
 * nothing of the asked type, and it is the answer browsers handle best: nothing
 * to try, so happy-eyeballs uses the A record it already has. A REFUSED, or a
 * dropped query, looks like a broken resolver and stalls the lookup or triggers
 * a retry. NODATA is only synthesized when [egressV4Only] is set.
 *
 * ## Caches
 *
 * [nameCache] holds positive A answers with the TTL the resolver itself
 * declared, so a cached entry can never outlive the real one. [nodataCache]
 * holds negative answers for [NODATA_TTL_S] — short, because a NODATA is a guess
 * about the near future rather than a fact about the name, and a browser that
 * re-asks AAAA five times in a second should not pay five round trips but also
 * should not be wedged for minutes if the egress gained v6 mid-session.
 *
 * ## Deliberately not shared with [WarpUdpgwFront]
 *
 * That class's byte counters feed WARP watchdogs. Sharing them would make this
 * front's DNS traffic look like WARP traffic, the same mistake the SHARD/WARP
 * split already warned about, so this class keeps its own.
 */
object SmartDnsFront {

    private const val TAG = "SmartDnsFront"

    /** RFC 1928 constants. */
    private const val SOCKS_VERSION = 5
    private const val CMD_CONNECT = 1
    private const val CMD_UDP_ASSOCIATE = 3
    private const val ATYP_IPV4 = 1
    private const val ATYP_DOMAIN = 3
    private const val ATYP_IPV6 = 4
    private const val REP_SUCCESS = 0
    private const val REP_GENERAL_FAILURE = 1

    /**
     * The loopback port this front binds, in front of aether on
     * [CoreConfig.SOCKS_PORT] (1819).
     *
     * 1827 is the next free slot in the app's internal block: 1819 aether,
     * 1820 the chained outer leg, 1822/1823 Tor, 1824 xray under SHARD, 1825
     * [ShardSocksFront], 1826 the anytls sidecar. Only one listener can occupy
     * a port, so this must not duplicate anything that can be up at the same
     * time — and this front only runs on the Hev/Zeptun WARP path, where none
     * of those are bound. [CoreConfig.RESERVED_PORTS] keeps the user's own port
     * box off it too.
     */
    const val LISTEN_PORT = 1827

    /**
     * The port a CONNECT/UDP ASSOCIATE must target to be treated as DNS by this
     * front. The TUN publishes [CoreConfig.SMART_DNS_RESOLVER] as its resolver,
     * and the engine turns queries to it into SOCKS requests that land here.
     */
    private const val DNS_PORT = 53

    private const val RELAY_BUFFER = 32 * 1024
    private const val UPSTREAM_CONNECT_TIMEOUT_MS = 15_000

    /** Largest datagram we will relay. Above the Ethernet MTU, below jumbo. */
    private const val UDP_BUFFER = 4096

    /**
     * Ceiling on concurrent client sessions.
     *
     * tun2socks lwIP runs a 256-entry connection table; staying well under it
     * means this front runs out of client slots before it does, rather than
     * holding sockets for table entries the client has already recycled. Each
     * session is a pool task, so this is also the ceiling on live threads.
     */
    private const val MAX_CLIENTS = 64

    /**
     * DNS worker pool size.
     *
     * Bounded on purpose: each task holds one UDP socket for at most
     * [DNS_TIMEOUT_MS], and a page-load burst must not become an unbounded
     * thread count on a phone. 8 concurrent lookups is more than a browser
     * usefully pipelines through one tunnel.
     */
    private const val WORKERS = 8

    /**
     * How long an idle UDP association is kept.
     *
     * Each holds a TCP control socket plus a UDP socket, so they cannot be
     * immortal — see the same reasoning in [ShardSocksFront].
     */
    private const val UDP_IDLE_TIMEOUT_MS = 60_000L

    /** How long a resolver round trip is allowed to take. */
    private const val DNS_TIMEOUT_MS = 10_000

    /** How long a negative (NODATA) answer is remembered. */
    private const val NODATA_TTL_S = 30

    /**
     * Public resolvers used for the lookups this front performs itself.
     *
     * Reached *through* aether's UDP ASSOCIATE, so the query leaves from the
     * egress and is neither visible to nor answerable by the carrier — the same
     * property [ShardSocksFront] and [TorSocksFront] keep. 1.1.1.1 with 8.8.8.8
     * behind it, the pair the rest of the app forces.
     */
    private val UPSTREAM_RESOLVERS = listOf("1.1.1.1", "8.8.8.8")

    /**
     * Networks that must never be sent into the tunnel.
     *
     * The engine turns the TUN's own addresses into SOCKS requests, and
     * relaying those to aether would send them through the tunnel to a
     * destination that exists only on this phone — the exact failure
     * [ShardSocksFront] hit with the TUN resolver 10.0.0.2. Answering DNS for
     * them is correct; relaying a CONNECT elsewhere is not.
     */
    private val directNets = listOf(
        "127.0.0.0/8", // loopback — this front, aether, the engines
        "10.0.0.0/8", // the TUN's own RFC1918 subnet (10.0.0.2 is the router)
        "172.16.0.0/12", // WARP CGNAT and a common LAN range
        "192.168.0.0/16", // the LAN the kill switch excludes
        "198.18.0.0/15", // Hev's mapdns (198.18.0.2) and benchmarking
    )

    /**
     * Whether the egress can reach IPv6 destinations.
     *
     * Read once at [start]: aether runs an IPv4-only netstack for the whole
     * session, so the answer cannot change while we are up. Kept as a field
     * with a reader so a future dual-stack egress can flip it without touching
     * the call sites.
     */
    @Volatile
    private var egressV4Only = true

    private fun isEgressV4Only(): Boolean = egressV4Only

    private val running = AtomicBoolean(false)

    @Volatile
    private var serverSocket: ServerSocket? = null

    /** aether's SOCKS listener, [CoreConfig.SOCKS_PORT]. */
    @Volatile
    private var upstreamPort: Int = 0

    /**
     * The encrypted-DNS resolver, or null when the session has only plain resolvers.
     *
     * Built in [start] from the user's DNS preference. When it is null the front
     * answers the device's DNS itself over plain UDP through aether, which is
     * what every session before encrypted DNS did.
     */
    @Volatile
    private var resolver: SmartDnsResolver? = null

    @Volatile
    private var connPool: ExecutorService? = null

    @Volatile
    private var dnsPool: ExecutorService? = null

    /** Live client sessions; the [MAX_CLIENTS] ceiling. */
    private val liveClients = AtomicInteger(0)

    private val dnsSeq = AtomicInteger(0)

    // --------------------------------------------------------------- counters

    /**
     * Session byte counters. TCP relay bytes only, UDP excluded on purpose, for
     * the same reason [TorSocksFront] excludes DNS: a few hundred bytes of
     * lookups must not make a tunnel that resolves names but carries nothing
     * look alive.
     */
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)

    val sessionTx: Long get() = txBytes.get()
    val sessionRx: Long get() = rxBytes.get()

    /** Cumulative flow counts for the session; informational, for the log. */
    private val connectsRelayed = AtomicLong(0)
    private val associatesRelayed = AtomicLong(0)
    private val dnsAnswered = AtomicLong(0)
    private val dnsNodata = AtomicLong(0)
    private val dnsRelayed = AtomicLong(0)
    private val clientsRejected = AtomicLong(0)

    val connectsRelayedTotal: Long get() = connectsRelayed.get()
    val associatesRelayedTotal: Long get() = associatesRelayed.get()
    val dnsAnsweredTotal: Long get() = dnsAnswered.get()
    val dnsNodataTotal: Long get() = dnsNodata.get()
    val dnsRelayedTotal: Long get() = dnsRelayed.get()
    val clientsRejectedTotal: Long get() = clientsRejected.get()

    val isRunning: Boolean
        get() = running.get()

    /**
     * @param socksPort aether's SOCKS listener ([CoreConfig.SOCKS_PORT]).
     */
    @Synchronized
    fun start(socksPort: Int): Boolean = start(null, null, socksPort)

    /**
     * Bring the front up with the user's encrypted resolvers.
     *
     * @param context used only to read the DNS preference
     * @param config the effective core config JSON, read for `dns_servers`
     * @param socksPort aether's SOCKS listener ([CoreConfig.SOCKS_PORT])
     */
    @Synchronized
    fun start(context: android.content.Context?, config: String?, socksPort: Int): Boolean {
        if (running.get()) {
            record("$TAG already running")
            return true
        }
        upstreamPort = socksPort
        egressV4Only = true // aether's netstack is IPv4-only for the whole session
        resolver = buildResolver(context, config)

        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), LISTEN_PORT))
            }
        } catch (e: Exception) {
            record("$TAG could not bind 127.0.0.1:$LISTEN_PORT: ${e.message}")
            return false
        }

        serverSocket = server
        connPool = Executors.newCachedThreadPool()
        dnsPool = Executors.newFixedThreadPool(WORKERS)
        txBytes.set(0)
        rxBytes.set(0)
        liveClients.set(0)
        nameCache.clear()
        nodataCache.clear()
        associations.clear()
        running.set(true)

        // Idle associations hold a TCP control socket plus a UDP socket each, so
        // they cannot be immortal — the same failure [ShardSocksFront] hit from
        // the other direction, where never-expiring conids saturated badvpn's
        // 256-slot table. One reaper for the whole session; the table is usually
        // nearly empty, so the 20 s tick is the only cost.
        Thread({
            while (running.get()) {
                try {
                    Thread.sleep(UDP_IDLE_TIMEOUT_MS / 3)
                } catch (e: InterruptedException) {
                    return@Thread
                }
                if (associations.isEmpty()) continue
                val now = System.currentTimeMillis()
                associations.entries.removeAll { entry ->
                    val stale = now - entry.value.lastUsed > UDP_IDLE_TIMEOUT_MS
                    if (stale) entry.value.close()
                    stale
                }
            }
        }, "smartdns-front-reap").apply { isDaemon = true }.start()

        Thread({
            try {
                while (running.get()) {
                    val client = try {
                        server.accept()
                    } catch (e: Exception) {
                        if (running.get()) record("$TAG accept failed: ${e.message}")
                        break
                    }
                    // The ceiling is on live sessions. Refusing the 65th is
                    // recoverable — lwIP resets one flow and the app retries —
                    // and better than an unbounded thread count on a phone.
                    // Counted so a leak is visible in the log.
                    if (liveClients.get() >= MAX_CLIENTS) {
                        clientsRejected.incrementAndGet()
                        closeQuietly(client)
                        continue
                    }
                    val pool = connPool
                    if (pool == null) {
                        closeQuietly(client)
                        break
                    }
                    try {
                        liveClients.incrementAndGet()
                        pool.execute {
                            // A pool task's uncaught exception reaches the
                            // worker's default handler and kills the process.
                            // One dead flow must never do that.
                            try {
                                serve(client)
                            } catch (_: Throwable) {
                                closeQuietly(client)
                            } finally {
                                liveClients.decrementAndGet()
                            }
                        }
                    } catch (e: RejectedExecutionException) {
                        liveClients.decrementAndGet()
                        closeQuietly(client)
                    } catch (e: Exception) {
                        liveClients.decrementAndGet()
                        closeQuietly(client)
                    }
                }
            } catch (t: Throwable) {
                record("$TAG accept loop ended: ${t.message}")
            }
        }, "smartdns-front-accept").apply { isDaemon = true }.start()

        record("$TAG listening on 127.0.0.1:$LISTEN_PORT → aether SOCKS $socksPort")
        return true
    }

    @Synchronized
    fun stop() {
        if (!running.getAndSet(false)) return
        closeQuietly(serverSocket)
        serverSocket = null
        connPool?.shutdownNow()
        connPool = null
        dnsPool?.shutdownNow()
        dnsPool = null
        associations.forEach { (_, association) -> association.close() }
        associations.clear()
        nameCache.clear()
        nodataCache.clear()
        record("$TAG stopped")
    }

    // ----------------------------------------------------------------- caches

    /**
     * Positive answers: name → IPv4, with the TTL the resolver declared.
     *
     * Keyed by the name lower-cased, because DNS is case-insensitive but
     * case-preserving and the cache must not miss on casing.
     */
    private val nameCache = ConcurrentHashMap<String, CachedAnswer>()

    private data class CachedAnswer(val address: ByteArray, val ttlSeconds: Int, val expiresAt: Long) {
        fun isLive(now: Long): Boolean = now < expiresAt
    }

    /**
     * Negative answers: a name+type already answered NODATA, and when.
     *
     * A browser re-asks AAAA for the same name several times in a second; the
     * cache makes the second ask free without wedging it for minutes if the
     * egress gained v6 mid-session.
     */
    private val nodataCache = ConcurrentHashMap<String, Long>()

    private fun nodataKey(name: String, type: Int) = "${name.lowercase()}|$type"

    // ---------------------------------------------------------------- directNets

    /** Whether [host] is inside a [directNets] range and must not be tunnelled. */
    private fun isDirect(host: String): Boolean {
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
        if (address.address.size != 4) return false // every entry is v4
        return directNets.any { cidr -> inRange(address, cidr) }
    }

    /** Single CIDR containment, IPv4 only. */
    private fun inRange(address: InetAddress, cidr: String): Boolean {
        val (base, prefix) = cidr.split("/")
        val baseAddress = runCatching { InetAddress.getByName(base) }.getOrNull() ?: return false
        val bits = prefix.toIntOrNull() ?: return false
        if (baseAddress.address.size != 4) return false
        if (bits < 0 || bits > 32) return false
        // 0 bits matches everything; any other mask keeps its high `bits` set.
        val mask = if (bits == 0) 0 else (-1 shl (32 - bits))
        return (ipv4ToInt(address.address) and mask) == (ipv4ToInt(baseAddress.address) and mask)
    }

    private fun ipv4ToInt(bytes: ByteArray): Int =
        ((bytes[0].toInt() and 0xFF) shl 24) or
            ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or
            (bytes[3].toInt() and 0xFF)

    // ---------------------------------------------------------------- SOCKS5

    private fun serve(client: Socket) {
        try {
            client.tcpNoDelay = true
            val input = DataInputStream(BufferedInputStream(client.getInputStream()))
            val output = BufferedOutputStream(client.getOutputStream())

            // Greeting. The engines offer "no authentication" only, because no
            // credentials are passed to them.
            if (input.read() != SOCKS_VERSION) {
                closeQuietly(client)
                return
            }
            val methodCount = input.read()
            if (methodCount < 0) {
                closeQuietly(client)
                return
            }
            input.readFully(ByteArray(methodCount))
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0x00))
            output.flush()

            // Request.
            if (input.read() != SOCKS_VERSION) {
                closeQuietly(client)
                return
            }
            val command = input.read()
            input.read() // reserved
            val addressType = input.read()
            val host = when (addressType) {
                ATYP_IPV4 -> {
                    val bytes = ByteArray(4)
                    input.readFully(bytes)
                    InetAddress.getByAddress(bytes).hostAddress.orEmpty()
                }
                ATYP_IPV6 -> {
                    val bytes = ByteArray(16)
                    input.readFully(bytes)
                    InetAddress.getByAddress(bytes).hostAddress.orEmpty()
                }
                ATYP_DOMAIN -> {
                    val length = input.read()
                    if (length <= 0) {
                        closeQuietly(client)
                        return
                    }
                    val bytes = ByteArray(length)
                    input.readFully(bytes)
                    String(bytes, Charsets.US_ASCII)
                }
                else -> {
                    replyFailure(output, REP_GENERAL_FAILURE)
                    closeQuietly(client)
                    return
                }
            }
            val port = ((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)

            when (command) {
                CMD_CONNECT -> connect(client, host, port, output)
                CMD_UDP_ASSOCIATE -> udpAssociate(client, output)
                else -> {
                    // BIND is genuinely unused: nothing in this path issues it.
                    replyFailure(output, REP_GENERAL_FAILURE)
                    closeQuietly(client)
                }
            }
        } catch (_: Throwable) {
            closeQuietly(client)
        }
    }

    private fun replySuccess(output: OutputStream) {
        try {
            // Bound address 0.0.0.0:0 — the engines do not read it for CONNECT.
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), REP_SUCCESS.toByte(), 0,
                    ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0,
                )
            )
            output.flush()
        } catch (_: Exception) {
        }
    }

    private fun replyFailure(output: OutputStream, code: Int) {
        try {
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), code.toByte(), 0,
                    ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0,
                )
            )
            output.flush()
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------ TCP CONNECT

    /**
     * Handle a CONNECT.
     *
     * A CONNECT to the TUN's own resolver is the DNS-over-TCP channel, and it is
     * answered by this front. Everything else is relayed verbatim to aether,
     * which applies the routing rules and the tunnel — this front makes no
     * routing decision of its own.
     */
    private fun connect(client: Socket, host: String, port: Int, clientOut: OutputStream) {
        if (port == DNS_PORT && (host == resolverHost() || isDirect(host))) {
            // Report success first: the client waits for the SOCKS reply before
            // it starts framing queries onto the stream.
            replySuccess(clientOut)
            serveDnsConnect(client, DataInputStream(BufferedInputStream(client.getInputStream())), clientOut)
            return
        }

        // A CONNECT to a direct network would send a local address through the
        // tunnel, where it does not exist. Refuse it so lwIP resets this one
        // flow instead of hanging on a destination that can never answer.
        if (isDirect(host)) {
            replyFailure(clientOut, REP_GENERAL_FAILURE)
            closeQuietly(client)
            return
        }

        relayToUpstream(client, host, port, clientOut)
    }

    /**
     * Answer DNS-over-TCP on an established stream (RFC 1035 §4.2.2: a two-byte
     * big-endian length prefix, then the message).
     *
     * A is answered from [nameCache] or a real lookup. AAAA and HTTPS get NODATA
     * on a v4-only egress. Everything else is relayed verbatim to the upstream
     * resolver through aether, so a query type this front does not synthesize
     * still works.
     */
    private fun serveDnsConnect(client: Socket, input: DataInputStream, output: OutputStream) {
        try {
            while (running.get() && !client.isClosed) {
                val high = input.read()
                if (high < 0) break
                val low = input.read()
                if (low < 0) break
                val length = (high shl 8) or low
                if (length <= 0 || length > UDP_BUFFER) break
                val query = ByteArray(length)
                input.readFully(query)
                handleDnsQuery(query, object : DnsReply {
                    override fun send(reply: ByteArray) = writeTcpDns(output, reply)
                })
            }
        } catch (_: Throwable) {
            // Stream closed by the engine, or we are stopping.
        } finally {
            closeQuietly(client)
        }
    }

    /** Write a DNS message with its two-byte length prefix. */
    private fun writeTcpDns(output: OutputStream, message: ByteArray) {
        try {
            output.write((message.size shr 8) and 0xFF)
            output.write(message.size and 0xFF)
            output.write(message)
            output.flush()
        } catch (_: Exception) {
            // Stream gone; the read loop will notice and exit.
        }
    }

    // ------------------------------------------------------------ UDP

    /**
     * Handle a UDP ASSOCIATE.
     *
     * The bound address handed back is the relay socket the client must send its
     * datagrams to. It has to be reachable from the engine's own socket, and the
     * client is on this same machine, so loopback is correct and is what a real
     * SOCKS server on a single host would answer.
     */
    private fun udpAssociate(client: Socket, clientOut: OutputStream) {
        val relay = try {
            DatagramSocket().apply { bind(InetSocketAddress("127.0.0.1", 0)) }
        } catch (e: Exception) {
            replyFailure(clientOut, REP_GENERAL_FAILURE)
            closeQuietly(client)
            return
        }

        try {
            val localPort = relay.localPort
            clientOut.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), REP_SUCCESS.toByte(), 0,
                    ATYP_IPV4.toByte(), 127, 0, 0, 1,
                    ((localPort shr 8) and 0xFF).toByte(), (localPort and 0xFF).toByte(),
                )
            )
            clientOut.flush()
        } catch (e: Exception) {
            replyFailure(clientOut, REP_GENERAL_FAILURE)
            closeQuietly(client)
            closeQuietly(relay)
            return
        }

        associatesRelayed.incrementAndGet()
        serveUdpAssociate(client, relay)
    }

    /**
     * Pump datagrams for one UDP ASSOCIATE.
     *
     * One association per client session, keyed by the client socket. Port-53
     * datagrams aimed at the TUN resolver are answered here; everything else is
     * relayed to aether verbatim, so QUIC, Telegram calls and games work.
     */
    private fun serveUdpAssociate(client: Socket, relay: DatagramSocket) {
        val key = System.identityHashCode(client)
        val association = openAssociation(key, client) ?: run {
            closeQuietly(client)
            closeQuietly(relay)
            return
        }

        // Client → upstream. Each datagram is a SOCKS5 UDP request header plus
        // the payload (RFC 1928 §7).
        Thread({
            val buffer = ByteArray(UDP_BUFFER)
            try {
                while (running.get() && !relay.isClosed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    relay.receive(packet)
                    association.lastUsed = System.currentTimeMillis()
                    val request = packet.data.copyOfRange(0, packet.length)
                    handleUdpRequest(association, request, object : DnsReply {
                        override fun send(reply: ByteArray) = sendToClient(relay, reply)
                    })
                }
            } catch (_: Throwable) {
                // Per-flow; lwIP resets the stream.
            } finally {
                closeQuietly(relay)
                closeQuietly(client)
            }
        }, "smartdns-front-up-$key").apply { isDaemon = true }.start()

        // Upstream → client. aether's replies for the relayed flows land on the
        // association's socket; without this thread nothing forwards them back,
        // and QUIC, Telegram calls and games would send but never receive.
        Thread({
            val buffer = ByteArray(UDP_BUFFER)
            try {
                while (running.get() && !association.udp.isClosed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    association.udp.receive(packet)
                    association.lastUsed = System.currentTimeMillis()
                    // The reply names the responder, not what the app dialled;
                    // reframe it with the destination it asked about.
                    forwardToClient(relay, packet, association.clientAddress, association.clientPort)
                }
            } catch (_: Throwable) {
                // Per-flow; the client's receive loop notices a dead socket.
            } finally {
                closeQuietly(relay)
                closeQuietly(client)
            }
        }, "smartdns-front-down-$key").apply { isDaemon = true }.start()

        // Keep the control socket warm and detect teardown: the client closes it
        // to signal the association's end, and this is what notices.
        try {
            val upIn = DataInputStream(BufferedInputStream(client.getInputStream()))
            while (running.get() && !client.isClosed) {
                if (upIn.read() < 0) break
            }
        } catch (_: Throwable) {
        } finally {
            associations.remove(key)?.close()
            closeQuietly(relay)
            closeQuietly(client)
        }
    }

    /**
     * Route one SOCKS5 UDP request from the client.
     *
     * DNS for the TUN resolver is answered here; everything else is sent to
     * aether's relay address. Apps with hardcoded resolvers (8.8.8.8) are why
     * port 53 for a *non*-resolver address is relayed rather than intercepted.
     */
    private fun handleUdpRequest(
        association: Association,
        request: ByteArray,
        reply: DnsReply,
    ) {
        val parsed = parseUdpRequest(request) ?: return
        val payload = parsed.payload
        if (payload.isEmpty()) return

        // Remember what this flow asked about, so aether's reply can be reframed
        // with it on the way back (see the down-thread in
        // [serveUdpAssociate]). Written only from this up-thread.
        association.clientAddress = parsed.address
        association.clientPort = parsed.port

        if (parsed.port == DNS_PORT && (parsed.host == resolverHost() || isDirect(parsed.host))) {
            handleDnsQuery(payload, reply)
            return
        }

        if (payload.size > UDP_BUFFER) return

        // Forward the client's frame verbatim rather than rebuilding it: it is
        // already a well-formed SOCKS5 UDP request, and rebuilding it would risk
        // dropping an ATYP the rebuild does not handle.
        try {
            association.udp.send(
                DatagramPacket(request, request.size, association.relayHost, association.relayPort)
            )
        } catch (e: Exception) {
            associations.remove(associationKey(association))?.close()
        }
    }

    /**
     * Where a reply to this association's client must be sent.
     *
     * The reply is reframed for *this* association's client: the SOCKS5 UDP
     * header aether answered with names the resolver, not the address the app
     * dialled, and the client matches on the destination it asked about.
     */
    private fun sendToClient(relay: DatagramSocket, reply: ByteArray) {
        val frame = encapsulate(resolverAddress(), DNS_PORT, reply)
        try {
            relay.send(DatagramPacket(frame, frame.size))
        } catch (_: Exception) {
            // Per-datagram; the receive loop will notice a dead socket.
        }
    }

    /**
     * Forward one datagram from aether back to the client.
     *
     * aether's SOCKS5 UDP reply names the real responder (the resolver, or the
     * host the app dialled); the client is matching on what it asked about, so
     * the header is rebuilt with the destination it sent. This mirrors what
     * [ShardSocksFront.pumpAssociation] does for the same reason.
     */
    private fun forwardToClient(relay: DatagramSocket, packet: DatagramPacket, destination: InetAddress, port: Int) {
        val payload = decapsulate(packet.data, packet.length) ?: return
        val frame = encapsulate(destination, port, payload)
        try {
            relay.send(DatagramPacket(frame, frame.size))
        } catch (_: Exception) {
            // Per-datagram; the receive loop will notice a dead socket.
        }
    }

    /** The destination of one SOCKS5 UDP request, and its payload. */
    private data class UdpRequest(
        val address: InetAddress,
        val host: String,
        val port: Int,
        val payload: ByteArray,
    )

    /** Parse a SOCKS5 UDP request header. Returns null on anything malformed. */
    private fun parseUdpRequest(request: ByteArray): UdpRequest? {
        if (request.size < 10) return null
        if (request[0] != 0.toByte() || request[1] != 0.toByte()) return null
        if (request[2] != 0.toByte()) return null // FRAG != 0: nothing here emits fragments
        return when (request[3].toInt() and 0xFF) {
            ATYP_IPV4 -> {
                if (request.size < 10) return null
                val address = InetAddress.getByAddress(request.copyOfRange(4, 8))
                val port = ((request[8].toInt() and 0xFF) shl 8) or (request[9].toInt() and 0xFF)
                UdpRequest(address, address.hostAddress.orEmpty(), port, request.copyOfRange(10, request.size))
            }
            ATYP_IPV6 -> {
                if (request.size < 22) return null
                val address = InetAddress.getByAddress(request.copyOfRange(4, 20))
                val port = ((request[20].toInt() and 0xFF) shl 8) or (request[21].toInt() and 0xFF)
                UdpRequest(address, address.hostAddress.orEmpty(), port, request.copyOfRange(22, request.size))
            }
            ATYP_DOMAIN -> {
                val nameLength = request[4].toInt() and 0xFF
                if (request.size < 5 + nameLength + 2) return null
                val name = String(request.copyOfRange(5, 5 + nameLength), Charsets.US_ASCII)
                val port = ((request[5 + nameLength].toInt() and 0xFF) shl 8) or
                    (request[6 + nameLength].toInt() and 0xFF)
                val address = runCatching { InetAddress.getByName(name) }.getOrNull()
                    ?: return null
                UdpRequest(address, name, port, request.copyOfRange(7 + nameLength, request.size))
            }
            else -> null
        }
    }

    private fun associationKey(association: Association): Int =
        associations.entries.firstOrNull { it.value === association }?.key ?: -1

    // --------------------------------------------------------------- DNS core

    /** A reply sink, so the TCP and UDP paths can share one policy. */
    private fun interface DnsReply {
        fun send(reply: ByteArray)
    }

    /**
     * One DNS query, answered or relayed.
     *
     * This is the whole policy in one place, shared by CONNECT (DoT) and UDP
     * ASSOCIATE so the two cannot drift:
     *  - AAAA and HTTPS → NODATA, when the egress is v4-only.
     *  - A → a cached answer, or a real lookup.
     *  - anything else → relayed verbatim to the upstream resolver, so a type
     *    this front does not understand still gets a real answer.
     */
    private fun handleDnsQuery(query: ByteArray, reply: DnsReply) {
        if (query.size < 12) return
        val name = queryName(query) ?: return
        val type = queryType(query)

        // Negative cache: cheap, and the common case for AAAA on a browser.
        nodataCache[nodataKey(name, type)]?.let { marked ->
            if (System.currentTimeMillis() < marked) {
                dnsNodata.incrementAndGet()
                reply.send(nodataAnswer(query))
                return
            }
            nodataCache.remove(nodataKey(name, type))
        }

        if (isEgressV4Only() && (type == QTYPE_AAAA || type == QTYPE_HTTPS)) {
            nodataCache[nodataKey(name, type)] =
                System.currentTimeMillis() + NODATA_TTL_S * 1000L
            dnsNodata.incrementAndGet()
            reply.send(nodataAnswer(query))
            return
        }

        if (type == QTYPE_A) {
            val now = System.currentTimeMillis()
            nameCache[name.lowercase()]?.takeIf { it.isLive(now) }?.let { cached ->
                dnsAnswered.incrementAndGet()
                reply.send(aAnswer(query, cached.address, cached.ttlSeconds))
                return
            }
        }

        // Not answered from cache or policy. Ask the resolver on the bounded DNS
        // pool, so a slow resolver cannot pin a client relay thread.
        val pool = dnsPool ?: return
        try {
            pool.execute {
                try {
                    resolveThroughUpstream(query, name, type, reply)
                } catch (_: Throwable) {
                    // One dead query must not end the session.
                }
            }
        } catch (e: RejectedExecutionException) {
            // Shutting down.
        }
    }

    /**
     * Build the encrypted resolver from the user's DNS preference, or null when
     * the session has no encrypted entry — the front then answers DNS over plain
     * UDP through aether, exactly as it did before encrypted DNS existed.
     */
    private fun buildResolver(
        context: android.content.Context?,
        config: String?,
    ): SmartDnsResolver? {
        if (context == null || config == null) return null
        val raw = runCatching { org.json.JSONObject(config).optString("dns_servers").trim() }
            .getOrDefault("")
        if (raw.isEmpty()) return null
        val doh = SmartDnsServer.parse(raw, Transport.DOH)
        val dot = SmartDnsServer.parse(raw, Transport.DOT)
        val plain = SmartDnsServer.parse(raw, Transport.PLAIN)
        val servers = doh + dot + plain
        if (doh.isEmpty() && dot.isEmpty()) return null
        record(
            "$TAG encrypted DNS: ${doh.size} DoH, ${dot.size} DoT, ${plain.size} plain " +
                "(${servers.joinToString(", ") { it.label }})"
        )
        return SmartDnsResolver(
            servers = servers,
            upstreamHost = "127.0.0.1",
            upstreamPort = upstreamPort,
            autoFailover = true,
            onPathChange = { path ->
                record("$TAG resolver path → $path")
            },
        )
    }

    /**
     * Send [query] to the upstream resolver through aether and write its reply.
     *
     * For A, a successful lookup is also cached, so the second app to ask the
     * same name in this session is answered without a round trip. On any
     * failure the caller simply gets no reply, which is the same outcome a
     * broken resolver gives and what a dropped query falls back to.
     */
    private fun resolveThroughUpstream(query: ByteArray, name: String, type: Int, reply: DnsReply) {
        // Encrypted DNS: the query is answered by the user's DoT/DoH servers,
        // reached through the tunnel or directly, whichever the resolver picked.
        val encrypted = resolver
        if (encrypted != null) {
            val answer = encrypted.resolve(query)
            if (answer == null) {
                dnsRelayed.incrementAndGet()
                // Every server failed: say so rather than leaving the app to time out.
                SmartDnsMessage.servfailResponse(query)?.let { reply.send(it) }
                return
            }
            if (type == QTYPE_A) {
                parseFirstA(answer)?.let { (address, ttl) ->
                    nameCache[name.lowercase()] =
                        CachedAnswer(address, ttl, System.currentTimeMillis() + ttl * 1000L)
                }
            }
            dnsAnswered.incrementAndGet()
            reply.send(answer)
            return
        }
        val association = openDnsAssociation() ?: return
        val token = dnsSeq.incrementAndGet() and 0xFFFF
        val resolver = currentResolver()
        val datagram = encapsulate(resolver, DNS_PORT, rewriteId(query, token))
        val buffer = ByteArray(UDP_BUFFER)
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            association.udp.soTimeout = DNS_TIMEOUT_MS
            association.udp.send(
                DatagramPacket(datagram, datagram.size, association.relayHost, association.relayPort)
            )
            association.udp.receive(packet)
        } catch (e: Exception) {
            // The query goes unanswered. Apps retry, and DNS falls back to TCP.
            return
        }
        val response = decapsulate(buffer, packet.length) ?: return
        if (response.size < 12) return

        // Restore the app's own transaction id: the resolver echoes ours.
        response[0] = query[0]
        response[1] = query[1]

        if (type != QTYPE_A) {
            dnsRelayed.incrementAndGet()
            reply.send(response)
            return
        }
        val parsed = parseFirstA(response)
        if (parsed == null) {
            dnsRelayed.incrementAndGet()
            reply.send(response)
            return
        }
        val (address, ttl) = parsed
        nameCache[name.lowercase()] =
            CachedAnswer(address, ttl, System.currentTimeMillis() + ttl * 1000L)
        dnsAnswered.incrementAndGet()
        reply.send(response)
    }

    /**
     * Which resolver to ask. Alternating on a failure keeps one bad minute at a
     * single resolver from stalling every lookup this session.
     */
    @Volatile
    private var resolverIndex = 0

    private fun currentResolver(): InetAddress {
        val list = UPSTREAM_RESOLVERS
        val name = list[resolverIndex % list.size]
        return runCatching { InetAddress.getByName(name) }.getOrElse {
            InetAddress.getByName(list[(resolverIndex + 1) % list.size])
        }
    }

    // ---------------------------------------------------- UDP ASSOCIATE to aether

    private class Association(
        val control: Socket,
        val udp: DatagramSocket,
        val relayHost: InetAddress,
        val relayPort: Int,
        /** What the client asked about, to reframe aether's replies with. */
        var clientAddress: InetAddress = InetAddress.getByName("127.0.0.1"),
        var clientPort: Int = 0,
    ) {
        @Volatile
        var lastUsed: Long = System.currentTimeMillis()

        fun close() {
            try {
                udp.close()
            } catch (_: Exception) {
            }
            try {
                control.close()
            } catch (_: Exception) {
            }
        }
    }

    private val associations = ConcurrentHashMap<Int, Association>()

    /** A dedicated association for DNS, shared by every query this front asks. */
    private const val DNS_ASSOCIATION_KEY = -1

    /**
     * One shared UDP ASSOCIATE to aether for DNS, opened on first use.
     *
     * One for the whole session rather than one per query, for the same measured
     * reason [ShardSocksFront] shares its DNS channels: each associate costs a
     * full handshake, and a phone resolving names at the rate a browser does
     * would rebuild that many tunnels a minute.
     */
    private fun openDnsAssociation(): Association? {
        associations[DNS_ASSOCIATION_KEY]?.let { if (!it.udp.isClosed) return it }
        synchronized(associations) {
            associations[DNS_ASSOCIATION_KEY]?.let { if (!it.udp.isClosed) return it }
            val fresh = openAssociation(DNS_ASSOCIATION_KEY, control = null) ?: return null
            associations[DNS_ASSOCIATION_KEY] = fresh
            return fresh
        }
    }

    /**
     * Ask aether for a UDP ASSOCIATE and return the relay address to send to.
     *
     * Returns null when aether refuses UDP — some configurations do — in which
     * case that flow is simply dropped. A dropped flow is recoverable (apps
     * retry, and DNS falls back to TCP); a wrong association would corrupt every
     * later datagram on the same conid.
     *
     * @param control the client's control socket, whose lifetime scopes this
     *   association. null for the shared DNS association, which is owned by this
     *   front and closed in [stop].
     */
    private fun openAssociation(key: Int, control: Socket?): Association? {
        val upstream = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress("127.0.0.1", upstreamPort), UPSTREAM_CONNECT_TIMEOUT_MS)
            }
        } catch (e: Exception) {
            return null
        }

        return try {
            val upIn = DataInputStream(BufferedInputStream(upstream.getInputStream()))
            val upOut = BufferedOutputStream(upstream.getOutputStream())

            upOut.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, 0x00))
            upOut.flush()
            if (upIn.read() != SOCKS_VERSION || upIn.read() != 0x00) {
                closeQuietly(upstream)
                return null
            }

            // 0.0.0.0:0 as the bind address: we do not know which local port our
            // datagrams will leave from, and aether does not require us to.
            upOut.write(buildRequest(CMD_UDP_ASSOCIATE, "0.0.0.0", 0))
            upOut.flush()

            if (upIn.read() != SOCKS_VERSION) {
                closeQuietly(upstream)
                return null
            }
            val reply = upIn.read()
            upIn.read() // reserved
            if (reply != REP_SUCCESS) {
                closeQuietly(upstream)
                return null
            }

            // The relay address is the reply's bound address, and unlike CONNECT
            // it matters here — this is where datagrams have to be sent.
            var relayHost = InetAddress.getByName("127.0.0.1")
            when (upIn.read()) {
                ATYP_IPV4 -> {
                    val bytes = ByteArray(4)
                    upIn.readFully(bytes)
                    // aether may answer 0.0.0.0, meaning "same host as the
                    // control connection". Sending there would go nowhere.
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_IPV6 -> {
                    val bytes = ByteArray(16)
                    upIn.readFully(bytes)
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_DOMAIN -> {
                    val len = upIn.read()
                    if (len > 0) {
                        val bytes = ByteArray(len)
                        upIn.readFully(bytes)
                        relayHost = runCatching {
                            InetAddress.getByName(String(bytes, Charsets.US_ASCII))
                        }.getOrDefault(relayHost)
                    }
                }
                else -> {
                    closeQuietly(upstream)
                    return null
                }
            }
            val relayPort = ((upIn.read() and 0xFF) shl 8) or (upIn.read() and 0xFF)
            if (relayPort <= 0) {
                closeQuietly(upstream)
                return null
            }

            val udp = DatagramSocket()
            udp.soTimeout = 0
            val association = Association(upstream, udp, relayHost, relayPort)

            // Draining the client's control socket: the client closes it to
            // signal teardown, and without a reader we would keep feeding a dead
            // association. The shared DNS association has no client socket; it
            // is closed by [stop] and by a failed send.
            if (control != null) {
                Thread({
                    try {
                        val inStream = control.getInputStream()
                        val buffer = ByteArray(UDP_BUFFER)
                        while (running.get() && !control.isClosed) {
                            if (inStream.read(buffer) < 0) break
                        }
                    } catch (_: Throwable) {
                    } finally {
                        associations.remove(key, association)
                        association.close()
                    }
                }, "smartdns-front-ctl-$key").apply { isDaemon = true }.start()
            }

            association
        } catch (_: Throwable) {
            closeQuietly(upstream)
            null
        }
    }

    // ------------------------------------------------------------ TCP relay

    /**
     * A transparent pass-through to aether. Every byte is relayed as-is, so
     * aether still applies its routing rules and the tunnel; this front makes no
     * routing decision of its own.
     */
    private fun relayToUpstream(client: Socket, host: String, toPort: Int, clientOut: OutputStream) {
        connectsRelayed.incrementAndGet()
        val upstream = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress("127.0.0.1", upstreamPort), UPSTREAM_CONNECT_TIMEOUT_MS)
            }
        } catch (e: Exception) {
            replyFailure(clientOut, REP_GENERAL_FAILURE)
            closeQuietly(client)
            return
        }

        try {
            val upIn = DataInputStream(BufferedInputStream(upstream.getInputStream()))
            val upOut = BufferedOutputStream(upstream.getOutputStream())

            upOut.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, 0x00))
            upOut.flush()
            if (upIn.read() != SOCKS_VERSION || upIn.read() != 0x00) {
                replyFailure(clientOut, REP_GENERAL_FAILURE)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }

            upOut.write(buildRequest(CMD_CONNECT, host, toPort))
            upOut.flush()

            if (upIn.read() != SOCKS_VERSION) {
                replyFailure(clientOut, REP_GENERAL_FAILURE)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }
            val reply = upIn.read()
            upIn.read() // reserved
            skipBoundAddress(upIn)

            if (reply != REP_SUCCESS) {
                // Pass aether's own code back so lwIP resets this one flow
                // rather than retrying a dead destination forever.
                replyFailure(clientOut, reply)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }

            replySuccess(clientOut)

            // Resolved on THIS thread, not inside the pump lambda: a closed
            // socket makes getInputStream() throw, and as the first statement of
            // a bare thread body that throw reaches the default handler and
            // kills the process. That exact crash was seen in the field on the
            // Tor front.
            val clientIn = client.getInputStream()
            Thread({
                try {
                    pipe(clientIn, upOut, txBytes)
                } catch (_: Throwable) {
                } finally {
                    closeQuietly(upstream)
                    closeQuietly(client)
                }
            }, "smartdns-front-tcp-up").apply { isDaemon = true }.start()

            pipe(upIn, clientOut, rxBytes)
        } catch (_: Throwable) {
            // Per-flow; lwIP resets the stream.
        } finally {
            closeQuietly(upstream)
            closeQuietly(client)
        }
    }

    /** SOCKS5 request bytes for [command] toward [host]:[port]. */
    private fun buildRequest(command: Int, host: String, port: Int): ByteArray {
        val literal = runCatching { InetAddress.getByName(host) }.getOrNull()
            ?.takeIf { isIpLiteral(host) }
        return if (literal != null) {
            val bytes = literal.address
            ByteArray(4 + bytes.size + 2).apply {
                this[0] = SOCKS_VERSION.toByte()
                this[1] = command.toByte()
                this[2] = 0
                this[3] = (if (bytes.size == 16) ATYP_IPV6 else ATYP_IPV4).toByte()
                System.arraycopy(bytes, 0, this, 4, bytes.size)
                this[4 + bytes.size] = ((port shr 8) and 0xFF).toByte()
                this[5 + bytes.size] = (port and 0xFF).toByte()
            }
        } else {
            val name = host.toByteArray(Charsets.US_ASCII)
            ByteArray(5 + name.size + 2).apply {
                this[0] = SOCKS_VERSION.toByte()
                this[1] = command.toByte()
                this[2] = 0
                this[3] = ATYP_DOMAIN.toByte()
                this[4] = name.size.toByte()
                System.arraycopy(name, 0, this, 5, name.size)
                this[5 + name.size] = ((port shr 8) and 0xFF).toByte()
                this[6 + name.size] = (port and 0xFF).toByte()
            }
        }
    }

    private fun isIpLiteral(host: String): Boolean =
        host.indexOf(':') >= 0 || Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)

    /** Consume a SOCKS5 reply's bound address so the stream sits at the payload. */
    private fun skipBoundAddress(input: DataInputStream) {
        when (input.read()) {
            ATYP_IPV4 -> input.readFully(ByteArray(4))
            ATYP_IPV6 -> input.readFully(ByteArray(16))
            ATYP_DOMAIN -> {
                val length = input.read()
                if (length > 0) input.readFully(ByteArray(length))
            }
        }
        input.readFully(ByteArray(2))
    }

    private fun pipe(from: InputStream, to: OutputStream, counter: AtomicLong) {
        val buffer = ByteArray(RELAY_BUFFER)
        try {
            while (true) {
                val read = from.read(buffer)
                if (read < 0) return
                to.write(buffer, 0, read)
                to.flush()
                counter.addAndGet(read.toLong())
            }
        } catch (_: Exception) {
        }
    }

    // --------------------------------------------------------------- UDP wire

    /** Wrap a payload in a SOCKS5 UDP request header (RFC 1928 §7) for aether. */
    private fun encapsulate(destination: InetAddress, port: Int, payload: ByteArray): ByteArray {
        val address = destination.address
        val header = 4 + address.size + 2
        return ByteArray(header + payload.size).apply {
            // RSV RSV FRAG
            this[0] = 0
            this[1] = 0
            this[2] = 0
            this[3] = (if (address.size == 16) ATYP_IPV6 else ATYP_IPV4).toByte()
            System.arraycopy(address, 0, this, 4, address.size)
            this[4 + address.size] = ((port shr 8) and 0xFF).toByte()
            this[5 + address.size] = (port and 0xFF).toByte()
            System.arraycopy(payload, 0, this, header, payload.size)
        }
    }

    /**
     * Strip the SOCKS5 UDP reply header.
     *
     * Fragmented replies (FRAG != 0) are dropped: nothing in this path emits
     * them, and reassembling them wrongly is worse than losing a datagram.
     */
    private fun decapsulate(buffer: ByteArray, length: Int): ByteArray? {
        if (length < 10) return null
        if (buffer[2] != 0.toByte()) return null
        val header = when (buffer[3].toInt() and 0xFF) {
            ATYP_IPV4 -> 10
            ATYP_IPV6 -> 22
            ATYP_DOMAIN -> {
                val nameLength = buffer[4].toInt() and 0xFF
                5 + nameLength + 2
            }
            else -> return null
        }
        if (length <= header) return null
        return buffer.copyOfRange(header, length)
    }

    // --------------------------------------------------------------- DNS build

    /** QTYPE values this front has a policy for. */
    private const val QTYPE_A = 1
    private const val QTYPE_AAAA = 28
    private const val QTYPE_HTTPS = 65

    private fun resolverHost(): String = CoreConfig.SMART_DNS_RESOLVER

    private fun resolverAddress(): InetAddress =
        runCatching { InetAddress.getByName(resolverHost()) }
            .getOrDefault(InetAddress.getByName("127.0.0.1"))

    /** Read the QNAME out of a query as a dotted name. Returns null on garbage. */
    private fun queryName(query: ByteArray): String? {
        if (query.size < 12) return null
        val out = StringBuilder()
        var position = 12
        while (position < query.size) {
            val label = query[position].toInt() and 0xFF
            if (label == 0) break
            // A compression pointer is not valid in a question's QNAME.
            if (label and 0xC0 != 0) return null
            if (position + 1 + label > query.size) return null
            if (out.isNotEmpty()) out.append('.')
            for (i in 1..label) {
                out.append((query[position + i].toInt() and 0xFF).toChar())
            }
            position += 1 + label
        }
        return out.toString()
    }

    /** Read the QTYPE out of a query. Returns 0 if the message is too short. */
    private fun queryType(query: ByteArray): Int {
        if (query.size < 14) return 0
        // QTYPE sits after QNAME, which ends at the first zero label; find it
        // rather than assuming a fixed offset.
        var position = 12
        while (position < query.size - 4) {
            val label = query[position].toInt() and 0xFF
            if (label == 0) {
                val typeHigh = query[position + 1]
                val typeLow = query[position + 2]
                return ((typeHigh.toInt() and 0xFF) shl 8) or (typeLow.toInt() and 0xFF)
            }
            if (label and 0xC0 != 0) return 0
            if (position + 1 + label > query.size) return 0
            position += 1 + label
        }
        return 0
    }

    /**
     * A NODATA answer: NOERROR, no records.
     *
     * Built by copying the query and rewriting the header bits, which keeps the
     * question section byte-identical to what the app asked — the safest way to
     * build a reply a resolver library will accept.
     */
    private fun nodataAnswer(query: ByteArray): ByteArray {
        val out = query.copyOf()
        out[2] = 0x81.toByte() // response, recursion desired
        out[3] = 0x80.toByte() // recursion available, no records
        out[6] = 0 // ANCOUNT high
        out[7] = 0 // ANCOUNT low
        return out
    }

    /**
     * A synthesized A answer for the query's own question.
     *
     * The question section is copied from the query, so the reply matches what
     * the app asked even if it used an unusual label form.
     */
    private fun aAnswer(query: ByteArray, address: ByteArray, ttl: Int): ByteArray {
        // header(12) + the question as-is + a 16-byte A record.
        val out = ByteArray(12 + (query.size - 12) + 16)
        out[0] = query[0] // echo the app's transaction id
        out[1] = query[1]
        out[2] = 0x81.toByte() // response, recursion desired
        out[3] = 0x80.toByte() // recursion available
        out[5] = 1 // QDCOUNT
        out[7] = 1 // ANCOUNT
        System.arraycopy(query, 12, out, 12, query.size - 12)
        var at = query.size
        // The name, compressed to a pointer at offset 12 (the query's QNAME).
        out[at++] = 0xC0.toByte()
        out[at++] = 12
        out[at++] = 0 // TYPE high
        out[at++] = 1 // TYPE low: A
        out[at++] = 0 // CLASS high
        out[at++] = 1 // CLASS low: IN
        out[at++] = ((ttl shr 24) and 0xFF).toByte()
        out[at++] = ((ttl shr 16) and 0xFF).toByte()
        out[at++] = ((ttl shr 8) and 0xFF).toByte()
        out[at++] = (ttl and 0xFF).toByte()
        out[at++] = 0 // RDLENGTH high
        out[at++] = 4 // RDLENGTH low
        System.arraycopy(address, 0, out, at, 4)
        return out
    }

    /** Rewrite a query's transaction id, returning a copy. */
    private fun rewriteId(query: ByteArray, id: Int): ByteArray {
        val out = query.copyOf()
        out[0] = ((id shr 8) and 0xFF).toByte()
        out[1] = (id and 0xFF).toByte()
        return out
    }

    /** The first A record in a resolver reply: its address and TTL, or null. */
    private fun parseFirstA(reply: ByteArray): Pair<ByteArray, Int>? {
        if (reply.size < 12) return null
        val qdcount = ((reply[4].toInt() and 0xFF) shl 8) or (reply[5].toInt() and 0xFF)
        val ancount = ((reply[6].toInt() and 0xFF) shl 8) or (reply[7].toInt() and 0xFF)
        if (ancount == 0) return null
        // Skip the question section.
        var at = 12
        repeat(qdcount) {
            at = skipName(reply, at) ?: return null
            at += 4 // QTYPE + QCLASS
        }
        repeat(ancount) {
            at = skipName(reply, at) ?: return null
            if (at + 10 > reply.size) return null
            val type = ((reply[at].toInt() and 0xFF) shl 8) or (reply[at + 1].toInt() and 0xFF)
            val ttl = ((reply[at + 4].toInt() and 0xFF) shl 24) or
                ((reply[at + 5].toInt() and 0xFF) shl 16) or
                ((reply[at + 6].toInt() and 0xFF) shl 8) or
                (reply[at + 7].toInt() and 0xFF)
            val rdlength = ((reply[at + 8].toInt() and 0xFF) shl 8) or
                (reply[at + 9].toInt() and 0xFF)
            at += 10
            if (type == QTYPE_A && rdlength == 4 && at + 4 <= reply.size) {
                return Pair(reply.copyOfRange(at, at + 4), ttl)
            }
            if (at + rdlength > reply.size) return null
            at += rdlength
        }
        return null
    }

    /**
     * Skip a possibly-compressed domain name, returning the offset just past it
     * in the *original* stream, or null on garbage.
     *
     * Following a pointer means the name's bytes live elsewhere; the name still
     * ends where the pointer did, so the offset to resume from is the byte after
     * the pointer, not wherever the pointed-to labels terminate.
     */
    private fun skipName(reply: ByteArray, start: Int): Int? {
        var at = start
        var end = -1
        var jumps = 0
        while (at < reply.size) {
            val label = reply[at].toInt() and 0xFF
            if (label == 0) return if (end >= 0) end else at + 1
            if (label and 0xC0 != 0) {
                if (at + 1 >= reply.size) return null
                if (end < 0) end = at + 2
                val pointer = ((label and 0x3F) shl 8) or (reply[at + 1].toInt() and 0xFF)
                if (pointer >= reply.size || pointer < 12) return null
                at = pointer
                // A malformed reply can loop forever otherwise.
                if (++jumps > reply.size) return null
            } else {
                if (at + 1 + label > reply.size) return null
                at += 1 + label
            }
        }
        return null
    }

    private fun closeQuietly(closeable: java.io.Closeable?) {
        try {
            closeable?.close()
        } catch (_: Exception) {
        }
    }
}
