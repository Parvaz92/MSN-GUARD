package com.msnguard.vpn

import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The two egresses this resolver can reach a DNS server through.
 *
 * [TUNNEL] rides the engine's loopback SOCKS5 listener ([UPSTREAM_HOST]:[UPSTREAM_PORT]), so the
 * server sees the tunnel's exit address — the default, and what a resolver that serves anybody
 * expects. [DIRECT] opens the app's own sockets, which Android keeps outside the VPN, so the
 * server sees the phone's own carrier address. That second path is required by resolvers which
 * only answer local (Iranian) source IPs, and it is the reason the failover below exists.
 */
enum class Path {
    TUNNEL,
    DIRECT,
    ;

    /** The other path. Used by the failover streak, and what keeps the switch symmetric. */
    val other: Path
        get() = if (this == TUNNEL) DIRECT else TUNNEL
}

/**
 * Which wire format a [SmartDnsServer] speaks.
 *
 * [PLAIN] classic UDP/53, with a TCP re-ask when the answer comes back truncated (RFC 1035/7766).
 * [DOT]   DNS over TLS (RFC 7858): length-prefixed DNS inside TLS, port 853.
 * [DOH]   DNS over HTTPS (RFC 8484): the query is the body of an HTTP POST.
 */
enum class Transport(val defaultPort: Int) {
    PLAIN(53),
    DOT(853),
    DOH(443),
}

/**
 * One validated resolver.
 *
 * [host] is an IPv4 literal for PLAIN, and a literal or a host name for the encrypted transports
 * — the name is what TLS verifies against, and what the engine resolves inside the tunnel when the
 * stream is dialed through it. [path] is the URL path for DoH and is only read there.
 */
data class SmartDnsServer(
    val transport: Transport,
    val host: String,
    val port: Int,
    val path: String = DEFAULT_DOH_PATH,
) {
    /** `1.2.3.4`, `tls://dns.example`, `https://dns.example/dns-query` — the way the user typed it. */
    val label: String
        get() {
            val authority = if (port == transport.defaultPort) host else "$host:$port"
            return when (transport) {
                Transport.PLAIN -> authority
                Transport.DOT -> "tls://$authority"
                Transport.DOH -> "https://$authority$path"
            }
        }

    companion object {
        /** The path a DoH entry is given when it does not name one of its own. */
        const val DEFAULT_DOH_PATH = "/dns-query"

        /** At most this many servers are kept; they are tried in list order. */
        const val MAX_SERVERS = 8

        private val OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)"
        private val IPV4 = Regex("^$OCTET(?:\\.$OCTET){3}$")
        private val LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        private val HOSTNAME = Regex("^$LABEL(?:\\.$LABEL)+$")
        private val DOH_PATH = Regex("^/[A-Za-z0-9._~!&'()*+=:@%/-]*$")

        /**
         * The usable servers in [raw], in order, without duplicates, at most [MAX_SERVERS].
         * Separators are commas, spaces, semicolons and new lines. Anything that does not fit the
         * protocol's grammar is dropped rather than guessed at — one mistyped entry must not take
         * DNS away from the session.
         */
        fun parse(raw: String, transport: Transport): List<SmartDnsServer> = raw
            .split(',', ' ', ';', '\n', '\t', '\r')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .mapNotNull { parseOne(it, transport) }
            .distinct()
            .take(MAX_SERVERS)

        /** One entry for [transport], or null when it is not a legal server of that transport. */
        fun parseOne(entry: String, transport: Transport): SmartDnsServer? = when (transport) {
            Transport.PLAIN -> parsePlain(entry)
            Transport.DOT -> parseDot(entry)
            Transport.DOH -> parseDoh(entry)
        }

        private fun parsePlain(entry: String): SmartDnsServer? {
            val text = entry.lowercase().removePrefix("udp://").removePrefix("plain://")
            if (text.contains("://") || text.contains('/')) return null
            val (host, port) = splitHostPort(text, Transport.PLAIN.defaultPort) ?: return null
            if (!isIpv4(host) || !isUsableUnicast(host)) return null
            return SmartDnsServer(Transport.PLAIN, host, port)
        }

        private fun parseDot(entry: String): SmartDnsServer? {
            val text = entry.lowercase().removePrefix("tls://").removePrefix("dot://").trimEnd('/')
            if (text.contains("://") || text.contains('/')) return null
            val (host, port) = splitHostPort(text, Transport.DOT.defaultPort) ?: return null
            if (!isUsableHost(host)) return null
            return SmartDnsServer(Transport.DOT, host, port)
        }

        private fun parseDoh(entry: String): SmartDnsServer? {
            var text = entry.trim()
            if (text.lowercase().startsWith("https://")) {
                text = text.substring("https://".length)
            } else if (text.lowercase().startsWith("doh:")) {
                text = text.substring("doh:".length)
            } else if (text.contains("://")) {
                return null
            }
            text = text.replace("{?dns}", "")
            if (text.contains('@')) return null
            val slash = text.indexOf('/')
            val authority = (if (slash >= 0) text.substring(0, slash) else text).lowercase()
            var path = if (slash >= 0) text.substring(slash) else ""
            if (path.isEmpty() || path == "/") path = DEFAULT_DOH_PATH
            if (!DOH_PATH.matches(path)) return null
            val (host, port) = splitHostPort(authority, Transport.DOH.defaultPort) ?: return null
            if (!isUsableHost(host)) return null
            return SmartDnsServer(Transport.DOH, host, port, path)
        }

        /** `host` or `host:port`; null for an empty host, an IPv6 literal, or a bad port. */
        private fun splitHostPort(text: String, defaultPort: Int): Pair<String, Int>? {
            if (text.isEmpty()) return null
            val colon = text.lastIndexOf(':')
            if (colon < 0) return text to defaultPort
            val host = text.substring(0, colon)
            val portText = text.substring(colon + 1)
            if (host.isEmpty() || host.contains(':')) return null
            if (portText.isEmpty() || portText.length > 5 || !portText.all { it in '0'..'9' }) return null
            val port = portText.toInt()
            if (port !in 1..65_535) return null
            return host to port
        }

        private fun isUsableHost(host: String): Boolean =
            if (isIpv4(host)) isUsableUnicast(host) else isHostname(host)

        /** LDH labels, at least two, and a top-level label that is not all digits. */
        private fun isHostname(host: String): Boolean {
            if (host.length > 253 || !HOSTNAME.matches(host)) return false
            return host.substringAfterLast('.').any { it in 'a'..'z' }
        }

        fun isIpv4(text: String): Boolean = IPV4.matches(text)

        /**
         * An IPv4 address that can actually be a resolver: not `0/8`, loopback `127/8`, link-local
         * `169.254/16`, CGNAT `100.64/10`, private `10/8` and `172.16/12` and `192.168/16`, or
         * `224` and up — multicast, reserved and the limited broadcast, none of which can answer a
         * query. The private ranges are excluded for the same reason: nothing behind the user's own
         * router is a public resolver, and the app would only list them by mistake.
         */
        fun isUsableUnicast(address: String): Boolean {
            if (!isIpv4(address)) return false
            val octets = address.split('.').map { it.toInt() }
            return when (val first = octets[0]) {
                0, 10, 127 -> false
                169 -> octets[1] != 254
                172 -> octets[1] !in 16..31
                192 -> octets[1] != 168
                100 -> {
                    // CGNAT is global in reach but reserved; a resolver there is not ours to use.
                    val second = octets[1]
                    second !in 64..127
                }
                else -> first < 224
            }
        }
    }
}

/**
 * Sends DNS queries to a list of servers over PLAIN / DoT / DoH on [path], and moves between the
 * two paths on its own when one of them stops answering.
 *
 * ### Why a resolver of our own
 *
 * Hev and Zeptun have no TLS stack, so a `tls://` / `https://` resolver the user set is invisible
 * to them. This class is the phone-side half that speaks those protocols: it answers the loopback
 * front ([SmartDnsFront]) that the engine forwards to, so the device's resolver still only ever
 * sends plain DNS to a TUN address and the encrypted work happens here.
 *
 * ### Failover
 *
 * Every query is tried on the current path first, inside [PRIMARY_BUDGET_MS]. When that fails and
 * the other path answers — inside [SECONDARY_BUDGET_MS] — the answer is used, and after
 * [SWITCH_AFTER] such rescues in a row the other path becomes the current one. The rule is sticky
 * and symmetric, so a server that starts answering through the tunnel again wins the session back
 * exactly the same way. [probe] makes the first decision up front, so a resolver that only serves
 * local addresses does not cost the first page load two timeouts.
 *
 * A REFUSED answer counts as a failure rather than an answer: RCODE 5 is precisely what a resolver
 * that does not serve this source address says, and handing it to an app would look like a
 * successful lookup that resolves nothing.
 *
 * ### Connections
 *
 * DoT, DoH and PLAIN-over-TCP sockets are pooled per `path|transport|host:port`, and a reused one
 * is only trusted when its answer's transaction id matches the question (DoT, TCP). A DoH answer
 * gets the query's own id written back into its first two bytes, because RFC 8484 permits a server
 * to answer with id 0 — without that, a pooled connection and an id check could not both work.
 *
 * TLS uses the platform trust store and the platform hostname verifier. Nothing here is
 * click-through: a certificate that does not match the server's name is a hard failure.
 *
 * Blocking throughout. Call it from a worker thread — the front already does.
 */
internal class SmartDnsResolver(
    private val servers: List<SmartDnsServer>,
    private val upstreamHost: String = UPSTREAM_HOST,
    private val upstreamPort: Int = UPSTREAM_PORT,
    private val autoFailover: Boolean = true,
    private val onPathChange: (Path) -> Unit = {},
) {
    /** The path every query is tried on first. Changes only through [switchTo]. */
    @Volatile
    var path: Path = Path.TUNNEL
        private set

    @Volatile
    private var closed = false

    /** Consecutive queries the other path had to rescue; reset to zero the moment the current one answers. */
    private val streak = AtomicInteger(0)
    private val pathLock = Any()

    private class Idle(val socket: Socket, val returnedAt: Long)

    /** `path|transport|host:port` -> idle sockets. Borrowed LIFO, so the warmest one is reused. */
    private val pool = HashMap<String, ArrayDeque<Idle>>()
    private val poolLock = Any()

    /** `path|server` -> warned, so one bad server logs once per path instead of once per query. */
    private val warned = ConcurrentHashMap<String, Boolean>()

    private val tlsFactory: SSLSocketFactory by lazy { SSLSocketFactory.getDefault() as SSLSocketFactory }

    /** An answer to [query], or null when no server answered on either path within budget. */
    fun resolve(query: ByteArray): ByteArray? {
        if (closed || servers.isEmpty()) return null
        val current = path
        val first = resolveOn(current, query, PRIMARY_BUDGET_MS)
        if (first != null) {
            streak.set(0)
            return first
        }
        if (!autoFailover || closed) return null
        val fallback = current.other
        val second = resolveOn(fallback, query, SECONDARY_BUDGET_MS) ?: return null
        if (streak.incrementAndGet() >= SWITCH_AFTER) {
            switchTo(fallback, "stopped answering ${describe(current)}, answering ${describe(fallback)}")
        }
        return second
    }

    /**
     * Decides the first path before any app asks: TUNNEL when the servers answer there, DIRECT when
     * they only answer there. Blocking; run it on a background thread.
     */
    fun probe() {
        if (!autoFailover || servers.isEmpty()) return
        val query = SmartDnsMessage.buildQuery(PROBE_NAME, TYPE_A, PROBE_ID)
        if (resolveOn(Path.TUNNEL, query, PROBE_BUDGET_MS) != null) {
            Log.i(TAG, "Smart DNS answers through the tunnel; staying on the tunnel path.")
            return
        }
        if (closed) return
        if (resolveOn(Path.DIRECT, query, PROBE_BUDGET_MS) != null) {
            switchTo(Path.DIRECT, "no answer through the tunnel, but the direct path answers")
        } else {
            Log.w(
                TAG,
                "Smart DNS: no server answered through the tunnel or directly yet; " +
                    "every query keeps trying both paths.",
            )
        }
    }

    /**
     * An answer to [query] on [path], trying the servers in order for at most [budgetMs] in total.
     * Never switches paths — [resolve] owns that.
     */
    fun resolveOn(path: Path, query: ByteArray, budgetMs: Long): ByteArray? {
        val deadline = System.currentTimeMillis() + budgetMs
        for (server in servers) {
            if (closed) return null
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0L) break
            val timeout = remaining.coerceIn(MIN_ATTEMPT_MS, ATTEMPT_TIMEOUT_MS).toInt()
            // exchange() throwing is any socket failure; a null return is the transport
            // refusing to talk at all. Either way the next server gets a turn while the
            // budget still allows it.
            val answer = runCatching { exchange(path, server, query, timeout) }.getOrNull()
            if (answer != null && isUsable(query, answer)) {
                warned.remove(warnKey(path, server))
                return answer
            }
            warnOnce(path, server)
        }
        return null
    }

    /** Drops every pooled socket and refuses further work. Safe to call more than once. */
    fun close() {
        closed = true
        synchronized(poolLock) {
            pool.values.forEach { queue -> queue.forEach { runCatching { it.socket.close() } } }
            pool.clear()
        }
    }

    // --------------------------------------------------------------- failover

    private fun switchTo(target: Path, reason: String) {
        synchronized(pathLock) {
            if (path == target) return
            path = target
            streak.set(0)
        }
        Log.i(TAG, "Smart DNS now reaches the provider ${describe(target)}: $reason.")
        runCatching { onPathChange(target) }
    }

    private fun describe(path: Path): String =
        if (path == Path.TUNNEL) "through the tunnel" else "directly"

    /**
     * An answer worth handing to an app: it is a response, it answers the question that was asked,
     * and it is not a refusal. The transaction id check is what makes a pooled connection safe to
     * reuse — without it a second query on a reused stream could be handed the first query's reply.
     */
    private fun isUsable(query: ByteArray, answer: ByteArray?): Boolean =
        answer != null &&
            SmartDnsMessage.isResponse(answer) &&
            SmartDnsMessage.transactionId(answer) == SmartDnsMessage.transactionId(query) &&
            SmartDnsMessage.rcode(answer) != RCODE_REFUSED

    private fun warnKey(path: Path, server: SmartDnsServer): String = "${path.name}|${server.label}"

    private fun warnOnce(path: Path, server: SmartDnsServer) {
        if (warned.putIfAbsent(warnKey(path, server), true) == null) {
            Log.w(TAG, "Smart DNS server ${server.label} did not answer ${describe(path)}.")
        }
    }

    // --------------------------------------------------------------- exchanges

    private fun exchange(path: Path, server: SmartDnsServer, query: ByteArray, timeoutMs: Int): ByteArray? =
        when (server.transport) {
            Transport.PLAIN -> {
                // UDP first; a truncated answer means the server had more to say than fit, and
                // only TCP can carry the rest. The truncated answer is still returned if the TCP
                // re-ask fails, because partial is better than nothing for a name lookup.
                val answer = datagram(path, server, query, timeoutMs)
                if (answer != null && SmartDnsMessage.isTruncated(answer)) {
                    stream(path, server, query, timeoutMs, tls = false) ?: answer
                } else {
                    answer
                }
            }
            Transport.DOT -> stream(path, server, query, timeoutMs, tls = true)
            Transport.DOH -> doh(path, server, query, timeoutMs)
        }

    /**
     * PLAIN over UDP: our own datagram socket when DIRECT, or a SOCKS5 UDP ASSOCIATE through the
     * engine when TUNNEL. The association is short-lived by design — one query, one reply, then
     * the control connection goes away — because DNS is one datagram per exchange and a pooled
     * association would hold a port open against nothing.
     */
    private fun datagram(path: Path, server: SmartDnsServer, query: ByteArray, timeoutMs: Int): ByteArray? {
        val address = SmartSocksWire.ipv4Bytes(server.host) ?: return null
        if (path == Path.TUNNEL) return datagramThroughUpstream(address, server.port, query, timeoutMs)
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            socket.send(DatagramPacket(query, query.size, InetAddress.getByAddress(address), server.port))
            return receiveAnswer(socket, query) { buffer, length -> buffer.copyOf(length) }
        }
    }

    /**
     * UDP through the engine: open a control connection, greet, issue UDP ASSOCIATE, then send the
     * query as one SOCKS UDP datagram to the relay endpoint the engine reported. The reply is
     * unwrapped from its SOCKS header before it is checked.
     */
    private fun datagramThroughUpstream(
        address: ByteArray,
        port: Int,
        query: ByteArray,
        timeoutMs: Int,
    ): ByteArray? {
        Socket().use { control ->
            control.tcpNoDelay = true
            control.connect(InetSocketAddress(upstreamHost, upstreamPort), timeoutMs)
            control.soTimeout = timeoutMs
            val input = control.getInputStream()
            val output = control.getOutputStream()

            output.write(SmartSocksWire.greet())
            output.flush()
            if (!acceptGreetingReply(input)) return null

            output.write(SmartSocksWire.requestIpv4(SmartSocksWire.CMD_UDP_ASSOCIATE, ANY_ADDRESS, 0))
            output.flush()
            val relay = relayEndpoint(input) ?: return null

            DatagramSocket(InetSocketAddress(LOOPBACK, 0)).use { socket ->
                socket.soTimeout = timeoutMs
                val packet = SmartSocksWire.udpHeader(address, port, query)
                socket.send(DatagramPacket(packet, packet.size, relay.first, relay.second))
                return receiveAnswer(socket, query) { buffer, length ->
                    SmartSocksWire.parseUdp(buffer.copyOf(length))?.payload
                }
            }
        }
    }

    /**
     * The first datagram on [socket] that actually answers [query]. Late answers to earlier
     * questions on a shared relay are skipped rather than trusted, up to [DATAGRAM_RECEIVES].
     */
    private fun receiveAnswer(
        socket: DatagramSocket,
        query: ByteArray,
        unwrap: (ByteArray, Int) -> ByteArray?,
    ): ByteArray? {
        val buffer = ByteArray(MAX_MESSAGE_BYTES)
        val wanted = SmartDnsMessage.transactionId(query)
        repeat(DATAGRAM_RECEIVES) {
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            val message = unwrap(buffer, packet.length) ?: return@repeat
            if (SmartDnsMessage.transactionId(message) == wanted) return message
        }
        return null
    }

    /**
     * Length-prefixed DNS on a stream (RFC 7766): DoT when [tls], plain DNS over TCP otherwise.
     * Both are pooled — a TLS handshake is the expensive part of a DoT query, and reusing one
     * connection is what keeps DoT competitive with UDP on repeated lookups.
     */
    private fun stream(path: Path, server: SmartDnsServer, query: ByteArray, timeoutMs: Int, tls: Boolean): ByteArray? {
        val key = poolKey(path, if (tls) "dot" else "tcp", server)
        val pooled = borrow(key)
        if (pooled != null) {
            val answer = runCatching { framed(pooled, query, timeoutMs) }.getOrNull()
            if (answer != null) {
                release(key, pooled)
                return answer
            }
            // A reused connection that will not answer is closed, not returned: the fresh-open
            // path below is the recovery, and pooling a dead socket would just fail the next
            // query for the same reason.
            runCatching { pooled.close() }
        }
        val fresh = open(path, server.host, server.port, tls, timeoutMs) ?: return null
        val answer = runCatching { framed(fresh, query, timeoutMs) }.getOrNull()
        if (answer != null) release(key, fresh) else runCatching { fresh.close() }
        return answer
    }

    private fun framed(socket: Socket, query: ByteArray, timeoutMs: Int): ByteArray {
        socket.soTimeout = timeoutMs
        val output = socket.getOutputStream()
        // One write, so a TLS stack puts the length prefix and the message in a single record —
        // two writes make two records and doubles the post-handshake cost of every DoT query.
        output.write(SmartSocksWire.portBytes(query.size) + query)
        output.flush()
        val input = socket.getInputStream()
        val length = SmartSocksWire.readExact(input, 2) ?: throw IOException("truncated DNS length")
        val size = SmartSocksWire.u16(length, 0)
        if (size < DNS_HEADER_BYTES) throw IOException("bad DNS length")
        val answer = SmartSocksWire.readExact(input, size) ?: throw IOException("truncated DNS answer")
        if (SmartDnsMessage.transactionId(answer) != SmartDnsMessage.transactionId(query)) {
            throw IOException("DNS answer id does not match the question")
        }
        return answer
    }

    /**
     * DNS over HTTPS: an HTTP/1.1 POST of `application/dns-message` on a pooled TLS connection.
     * HTTP/2 is not attempted — the platform does not expose it without OkHttp, and keep-alive on
     * a pooled HTTP/1.1 connection is already the win HTTP/2 would give for one request at a time.
     */
    private fun doh(path: Path, server: SmartDnsServer, query: ByteArray, timeoutMs: Int): ByteArray? {
        val key = poolKey(path, "doh", server)
        val pooled = borrow(key)
        if (pooled != null) {
            val result = runCatching { dohOnce(pooled, server, query, timeoutMs) }.getOrNull()
            if (result != null) {
                keepOrClose(key, pooled, result.second)
                return result.first
            }
            runCatching { pooled.close() }
        }
        val fresh = open(path, server.host, server.port, tls = true, timeoutMs) ?: return null
        val result = runCatching { dohOnce(fresh, server, query, timeoutMs) }.getOrNull()
        if (result == null) {
            runCatching { fresh.close() }
            return null
        }
        keepOrClose(key, fresh, result.second)
        return result.first
    }

    /** One POST, returning the answer and whether the connection may serve the next one. */
    private fun dohOnce(socket: Socket, server: SmartDnsServer, query: ByteArray, timeoutMs: Int): Pair<ByteArray, Boolean> {
        socket.soTimeout = timeoutMs
        val output = socket.getOutputStream()
        output.write(dohRequest(server, query))
        output.flush()
        val response = readDohResponse(socket.getInputStream()) ?: throw IOException("no HTTP response")
        if (response.status != HTTP_OK) throw IOException("HTTP ${response.status}")
        val answer = response.body
        if (answer.size < DNS_HEADER_BYTES) throw IOException("short DNS answer")
        // RFC 8484 permits id 0. The query's own id is written back so the pooled-connection id
        // check and the front's question matching both see one consistent value.
        answer[0] = query[0]
        answer[1] = query[1]
        return answer to !response.close
    }

    private fun keepOrClose(key: String, socket: Socket, reusable: Boolean) {
        if (reusable) release(key, socket) else runCatching { socket.close() }
    }

    /**
     * A connected stream to [host]:[port] on [path], wrapped in verified TLS when [tls]. Returns
     * null on any failure — every caller is inside a runCatching anyway, but a null is what turns
     * a dead server into a skipped one rather than a propagated crash.
     */
    private fun open(path: Path, host: String, port: Int, tls: Boolean, timeoutMs: Int): Socket? {
        val raw = if (path == Path.DIRECT) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(host, port), timeoutMs)
            } catch (error: IOException) {
                runCatching { socket.close() }
                return null
            }
            socket
        } else {
            dialThrough(host, port, timeoutMs) ?: return null
        }
        raw.soTimeout = timeoutMs
        if (!tls) return raw
        return try {
            val secure = tlsFactory.createSocket(raw, host, port, true) as SSLSocket
            secure.soTimeout = timeoutMs
            secure.startHandshake()
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, secure.session)) {
                runCatching { secure.close() }
                throw SSLPeerUnverifiedException("certificate does not match $host")
            }
            secure
        } catch (error: IOException) {
            runCatching { raw.close() }
            null
        }
    }

    // ------------------------------------------------- SOCKS5 toward the engine

    /** The server's greeting reply is exactly two bytes: version, chosen method. */
    private fun acceptGreetingReply(input: InputStream): Boolean {
        val reply = SmartSocksWire.readExact(input, 2) ?: return false
        return (reply[0].toInt() and 0xFF) == SmartSocksWire.VERSION &&
            (reply[1].toInt() and 0xFF) == SmartSocksWire.METHOD_NONE
    }

    /**
     * The bound endpoint a UDP ASSOCIATE reply names, which is where datagrams must be sent.
     *
     * Read here rather than through [SmartSocksWire.readReply] because that method returns only the
     * REP field and the relay address is the half of this reply that matters: an engine that binds
     * a port other than the listener's reports it here, and sending to the listener port instead
     * would send a SOCKS datagram to a stream port.
     *
     * A bound address of `0.0.0.0` means "this host, port unspecified at the address level", so it
     * is read as [upstreamHost] — the engine is on loopback and datagrams cannot leave the phone.
     */
    private fun relayEndpoint(input: InputStream): Pair<InetAddress, Int>? {
        val header = SmartSocksWire.readExact(input, 4) ?: return null
        if ((header[0].toInt() and 0xFF) != SmartSocksWire.VERSION) return null
        if ((header[1].toInt() and 0xFF) != SmartSocksWire.REP_SUCCESS) return null
        val bound = when (header[3].toInt() and 0xFF) {
            SmartSocksWire.ATYP_IPV4 -> SmartSocksWire.readExact(input, 4) ?: return null
            else -> return null
        }
        val portBytes = SmartSocksWire.readExact(input, 2) ?: return null
        val port = SmartSocksWire.u16(portBytes, 0)
        val unspecified = bound.all { it == 0.toByte() }
        val address = if (unspecified) InetAddress.getByName(upstreamHost) else InetAddress.getByAddress(bound)
        return address to port
    }

    /**
     * A CONNECT through the engine to [host]:[port]. A name that is not an IPv4 literal is sent as
     * a domain, so the engine resolves it inside the tunnel — this app's own resolver is the thing
     * that would be asked otherwise, which is the bootstrapping problem a domain ATYP avoids.
     */
    private fun dialThrough(host: String, port: Int, timeoutMs: Int): Socket? {
        val socket = Socket()
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(upstreamHost, upstreamPort), timeoutMs)
            socket.soTimeout = timeoutMs
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            output.write(SmartSocksWire.greet())
            output.flush()
            if (!acceptGreetingReply(input)) throw IOException("upstream refused the greeting")
            output.write(SmartSocksWire.requestConnect(host, port))
            output.flush()
            if (SmartSocksWire.readReply(input) != SmartSocksWire.REP_SUCCESS) {
                throw IOException("upstream refused CONNECT to $host:$port")
            }
            return socket
        } catch (error: IOException) {
            runCatching { socket.close() }
            return null
        }
    }

    // -------------------------------------------------------------------- pool

    /** The pool key for a reusable stream. PLAIN datagrams are never pooled. */
    private fun poolKey(path: Path, proto: String, server: SmartDnsServer): String =
        "${path.name}|$proto|${server.host}:${server.port}"

    private fun borrow(key: String): Socket? {
        synchronized(poolLock) {
            val queue = pool[key] ?: return null
            var entry = queue.pollLast()
            while (entry != null) {
                val socket = entry.socket
                val idleFor = System.currentTimeMillis() - entry.returnedAt
                val stale = socket.isClosed || socket.isInputShutdown || idleFor > POOL_IDLE_MS
                if (!stale) return socket
                runCatching { socket.close() }
                entry = queue.pollLast()
            }
            return null
        }
    }

    private fun release(key: String, socket: Socket) {
        if (closed || socket.isClosed) {
            runCatching { socket.close() }
            return
        }
        synchronized(poolLock) {
            val queue = pool.getOrPut(key) { ArrayDeque() }
            if (queue.size >= POOL_MAX) {
                // The cap is per server and servers are capped at [SmartDnsServer.MAX_SERVERS],
                // so the pool is bounded in total as well.
                runCatching { socket.close() }
                return
            }
            queue.addLast(Idle(socket, System.currentTimeMillis()))
        }
    }

    // --------------------------------------------------- HTTP/1.1 (RFC 8484)

    private class Head(val status: Int, val contentLength: Int?, val chunked: Boolean, val close: Boolean)
    private class DohResponse(val status: Int, val body: ByteArray, val close: Boolean)

    /** The POST bytes for [query] to [server]. */
    private fun dohRequest(server: SmartDnsServer, query: ByteArray): ByteArray {
        val host = if (server.port == Transport.DOH.defaultPort) server.host else "${server.host}:${server.port}"
        val path = server.path.ifEmpty { SmartDnsServer.DEFAULT_DOH_PATH }
        val head = "POST $path HTTP/1.1\r\n" +
            "Host: $host\r\n" +
            "User-Agent: MSNGuard\r\n" +
            "Accept: application/dns-message\r\n" +
            "Content-Type: application/dns-message\r\n" +
            "Content-Length: ${query.size}\r\n" +
            "\r\n"
        return head.toByteArray(Charsets.US_ASCII) + query
    }

    /**
     * One response from [input]: 1xx interim responses are skipped, and the body is read by
     * Content-Length, chunked encoding, or to EOF — whichever the head says. Reads stop exactly at
     * the end of the body because the connection goes back in the pool, and a reader that read
     * ahead would swallow the start of the next response.
     */
    private fun readDohResponse(input: InputStream): DohResponse? {
        repeat(MAX_INTERIM_RESPONSES) {
            val text = readHead(input) ?: return null
            val head = parseHead(text) ?: return null
            if (head.status in 100..199) return@repeat
            val body = when {
                head.chunked -> readChunked(input)
                head.contentLength != null -> {
                    if (head.contentLength !in 0..MAX_MESSAGE_BYTES) return null
                    SmartSocksWire.readExact(input, head.contentLength)
                }
                else -> readToEnd(input)
            } ?: return null
            val close = head.close || (!head.chunked && head.contentLength == null)
            return DohResponse(head.status, body, close)
        }
        return null
    }

    /** Status line plus the three headers that decide how the body is framed. */
    private fun parseHead(text: String): Head? {
        val lines = text.split("\r\n").filter { it.isNotEmpty() }
        val statusLine = lines.firstOrNull() ?: return null
        val parts = statusLine.split(' ')
        if (parts.size < 2 || !parts[0].startsWith("HTTP/")) return null
        val status = parts[1].toIntOrNull() ?: return null
        var length: Int? = null
        var chunked = false
        var close = parts[0] == "HTTP/1.0"
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim().lowercase()
            when (name) {
                "content-length" -> length = value.toIntOrNull()
                "transfer-encoding" -> chunked = value.contains("chunked")
                "connection" -> {
                    if (value.contains("close")) close = true
                    if (value.contains("keep-alive")) close = false
                }
            }
        }
        return Head(status, length, chunked, close)
    }

    /** Byte by byte to the blank line, so nothing past the headers is consumed. */
    private fun readHead(input: InputStream): String? {
        val out = ByteArrayOutputStream()
        var matched = 0
        while (out.size() < MAX_HEAD_BYTES) {
            val b = input.read()
            if (b < 0) return null
            out.write(b)
            matched = when {
                b == '\r'.code && (matched == 0 || matched == 2) -> matched + 1
                b == '\n'.code && (matched == 1 || matched == 3) -> matched + 1
                b == '\r'.code -> 1
                else -> 0
            }
            if (matched == 4) return String(out.toByteArray(), Charsets.ISO_8859_1)
        }
        return null
    }

    private fun readChunked(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream()
        while (out.size() <= MAX_MESSAGE_BYTES) {
            val line = readLine(input) ?: return null
            val size = line.substringBefore(';').trim().toIntOrNull(16) ?: return null
            if (size < 0) return null
            if (size == 0) {
                repeat(MAX_TRAILER_LINES) {
                    val trailer = readLine(input) ?: return null
                    if (trailer.isEmpty()) return out.toByteArray()
                }
                return null
            }
            if (out.size() + size > MAX_MESSAGE_BYTES) return null
            val chunk = SmartSocksWire.readExact(input, size) ?: return null
            out.write(chunk, 0, chunk.size)
            // The CRLF after a chunk body is part of the framing and must be consumed,
            // or the next size line would be read from the wrong offset.
            readLine(input) ?: return null
        }
        return null
    }

    private fun readToEnd(input: InputStream): ByteArray? {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(READ_BUFFER_BYTES)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) return out.toByteArray()
            if (out.size() + read > MAX_MESSAGE_BYTES) return null
            out.write(buffer, 0, read)
        }
    }

    private fun readLine(input: InputStream): String? {
        val out = StringBuilder()
        while (out.length < MAX_LINE_BYTES) {
            val b = input.read()
            if (b < 0) return null
            if (b == '\n'.code) return out.toString().removeSuffix("\r")
            out.append(b.toChar())
        }
        return null
    }

    private companion object {
        const val TAG = "smartdns"

        /**
         * The engine's loopback SOCKS5 listener. [Path.TUNNEL] rides this for CONNECT (DoT/DoH)
         * and for UDP ASSOCIATE (PLAIN). Mirrors [CoreConfig.SOCKS_PORT].
         */
        const val UPSTREAM_HOST = "127.0.0.1"
        const val UPSTREAM_PORT = 1819

        /** Datagrams are bound to loopback so they cannot leave the phone. */
        const val LOOPBACK = "127.0.0.1"

        /**
         * Budgets. The current path gets the primary budget first; only then does the other path
         * get the secondary one. The primary is the smaller of the two on purpose: a path that
         * needs its whole budget to answer is already the wrong one, and the extra time is better
         * spent on its replacement. [PROBE_BUDGET_MS] sits between them — it runs once, before
         * anything is waiting on it, so it can afford to outwait a slow first handshake.
         */
        const val PRIMARY_BUDGET_MS = 2_000L
        const val SECONDARY_BUDGET_MS = 3_000L
        const val PROBE_BUDGET_MS = 2_500L

        /** Per-server ceiling, and the floor below which a budget remainder is not worth a socket. */
        const val ATTEMPT_TIMEOUT_MS = 2_000L
        const val MIN_ATTEMPT_MS = 250L

        /** Consecutive rescues by the other path before it becomes the current one. */
        const val SWITCH_AFTER = 3

        /** A pooled stream is dropped once it has been idle this long — a handshake is cheaper than a dead connection. */
        const val POOL_IDLE_MS = 30_000L

        /** Per server, per transport, per path. See [release] for why the total is bounded too. */
        const val POOL_MAX = 2

        const val MAX_MESSAGE_BYTES = 65_535
        const val MAX_HEAD_BYTES = 16 * 1024
        const val MAX_LINE_BYTES = 1_024
        const val READ_BUFFER_BYTES = 4_096
        const val MAX_INTERIM_RESPONSES = 4
        const val MAX_TRAILER_LINES = 32
        const val DATAGRAM_RECEIVES = 4
        const val DNS_HEADER_BYTES = 12
        const val HTTP_OK = 200

        /** QTYPE A. */
        const val TYPE_A = 1

        /** RCODE REFUSED: what a resolver that does not serve this client says. */
        const val RCODE_REFUSED = 5

        /** A name every sanctions-DNS provider covers, and one that is geo-blocked for Iran. */
        const val PROBE_NAME = "gemini.google.com"
        const val PROBE_ID = 0x5D05

        /** The SOCKS UDP ASSOCIATE client-address field: "any" — the engine does not read it. */
        val ANY_ADDRESS = ByteArray(4)
    }
}
