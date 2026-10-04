package com.msnguard.vpn

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * SOCKS5 bytes for the loopback front-ends — [SmartDnsFront] answering tun2socks and
 * [SmartDnsResolver] dialing the engine's own SOCKS listener.
 *
 * ## Why this exists
 *
 * The app speaks SOCKS5 in five places, and four of them wrote the same
 * one-off byte arrays. `ShardSocksFront` builds CONNECT and UDP ASSOCIATE
 * requests toward xray (`buildRequest`), strips their replies
 * (`skipBoundAddress`), wraps datagrams (`encapsulate`) and unwraps them
 * (`decapsulate`). `TorSocksFront` does the same toward Tor, minus UDP
 * (Tor has none). `ShardProbe` and `SmartSplit` each hand-roll a third copy
 * of the greeting plus a hostname CONNECT to measure a node. All correct,
 * all slightly different, all with the same single-byte traps: a signed Byte
 * read from the wire must be masked with 0xFF before it is used as an
 * unsigned length or port, and a port must be shifted before it is added.
 *
 * This holds the subset those callers need, once. It is pure JVM — only
 * `java.io` and `kotlin.text` — so the same code runs under a JVM unit test
 * and on the device.
 *
 * ## Scope
 *
 * CONNECT and UDP ASSOCIATE only. BIND exists in RFC 1928 and nowhere in
 * this app, so building it here would be dead code the compiler cannot see.
 *
 * No authentication. The listeners this talks to are all on 127.0.0.1 and
 * inside this process; the one method that would carry credentials is the
 * greeting, and it offers `NO AUTHENTICATION REQUIRED` only. Adding
 * username/password support means widening that, not adding a parallel path.
 *
 * IPv4 and domain only. IPv6 appears in exactly one place — the CONNECT a
 * domain-name target could not produce — and this class has no consumer for
 * it, so there is no ATYP=4 builder here.
 *
 * ## The two byte traps, both silent
 *
 * **Signed bytes.** `read()` on a stream returns an Int already unsigned,
 * but `reply[1]` on a ByteArray is a signed Byte: `0xFF` is `-1`, and
 * comparing it to `0xFF` is false. Every byte read out of a ByteArray here
 * goes through `and 0xFF` first. `readAddress` returns the ATYP as an
 * unsigned Int for the same reason — a caller matching it against `1`, `3`
 * and `4` would otherwise be comparing against negative numbers for two of
 * the three.
 *
 * **Truncation, not failure.** `readExact` returns null on a short read
 * rather than throwing, because a truncated handshake is normal on a
 * listener whose peer just went away — treating it as an exception forces
 * every caller to catch in order to say the same thing. Callers check for
 * null and answer the client with a failure reply instead.
 */
object SmartSocksWire {

    /** RFC 1928 version. Every method that reads it checks it first. */
    const val VERSION = 5

    /** Method: no authentication required. The only one this wire offers. */
    const val METHOD_NONE = 0

    /** Method: the server accepted none of the client's list. Not a failure code. */
    const val METHOD_NONE_ACCEPTABLE = 0xFF

    /** Command: establish a TCP connection. */
    const val CMD_CONNECT = 1

    /** Command: establish a UDP relay. */
    const val CMD_UDP_ASSOCIATE = 3

    /** Address type: a four-byte IPv4 address. */
    const val ATYP_IPV4 = 1

    /** Address type: a one-byte length followed by that many ASCII bytes. */
    const val ATYP_DOMAIN = 3

    /** Address type: sixteen bytes. Read but never built — see the class kdoc. */
    const val ATYP_IPV6 = 4

    /** Reply: succeeded. Everything else is a failure for the caller's purpose. */
    const val REP_SUCCESS = 0

    /** Reply: general failure. Sent when the cause is not one of the specific ones. */
    const val REP_GENERAL_FAILURE = 1

    /** Reply: the client asked for a command we do not implement. */
    const val REP_COMMAND_NOT_SUPPORTED = 7

    /** Reply: the ATYP in the request was not 1, 3 or 4. */
    const val REP_ADDRESS_NOT_SUPPORTED = 8

    /**
     * Four address bytes for an IPv4 literal, or null when [text] is not one.
     *
     * Returns null rather than a zero address because every caller's decision
     * is "is this an IP or a name", and an all-zero answer to that question is
     * indistinguishable from `0.0.0.0`, which the UDP path legitimately sends
     * (see [requestUdpAssociate]). `InetAddress.getByName` would also resolve a
     * *name* through the system resolver, which is exactly the DNS leak the
     * domain ATYP exists to avoid, so it is not used here.
     */
    fun ipv4Bytes(text: String): ByteArray? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0..3) {
            val part = parts[i]
            // A leading '+' parses as 0 in older JDKs and as a number in newer
            // ones, and a sign is not part of an address.
            if (part.isEmpty() || part.length > 3) return null
            if (part.any { it !in '0'..'9' }) return null
            val value = part.toIntOrNull() ?: return null
            if (value !in 0..255) return null
            out[i] = value.toByte()
        }
        return out
    }

    /** Dotted-quad text for four address bytes, or null when [bytes] is not four long. */
    fun ipv4Text(bytes: ByteArray): String? {
        if (bytes.size != 4) return null
        return buildString {
            for (i in 0..3) {
                if (i > 0) append('.')
                append(bytes[i].toInt() and 0xFF)
            }
        }
    }

    /** The 16-bit value at [index], big-endian and unsigned. */
    fun u16(bytes: ByteArray, index: Int): Int =
        ((bytes[index].toInt() and 0xFF) shl 8) or (bytes[index + 1].toInt() and 0xFF)

    /** [port] as two big-endian bytes. */
    fun portBytes(port: Int): ByteArray = byteArrayOf(
        ((port shr 8) and 0xFF).toByte(),
        (port and 0xFF).toByte(),
    )

    /**
     * Read exactly [count] bytes, or null if the stream ends first.
     *
     * A short read is reported as null rather than as a partial buffer because
     * the caller cannot use a partial handshake and must not mistake one for a
     * complete one. [count] is clamped at zero: a negative length is a
     * programming error, but turning it into an exception would make a caller
     * that computed it from a wire length handle two failure modes for one
     * event.
     */
    fun readExact(input: InputStream, count: Int): ByteArray? {
        if (count <= 0) return ByteArray(0)
        val buffer = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = try {
                input.read(buffer, read, count - read)
            } catch (_: IOException) {
                return null
            }
            if (n <= 0) return null
            read += n
        }
        return buffer
    }

    /**
     * The greeting a client sends: version 5, one method, no auth.
     *
     * Fixed at one method because nothing in this app offers another, and a
     * server that only accepts `NO AUTHENTICATION REQUIRED` is being told the
     * truth about this client.
     */
    fun greet(): ByteArray = byteArrayOf(VERSION.toByte(), 1, METHOD_NONE.toByte())

    /**
     * Read and accept a client greeting, replying on [output].
     *
     * Verifies the version, consumes the whole method list (the length byte is
     * itself variable, so a server that read a fixed number of bytes would
     * desynchronize the stream for every later client), and answers with
     * [METHOD_NONE]. Returns false — without writing anything — when the
     * greeting is not version 5 or the stream ends, so a caller can drop the
     * connection without having sent a partial reply it cannot take back.
     *
     * @return true when a version-5 greeting was read and a method reply written.
     */
    fun acceptGreeting(input: InputStream, output: OutputStream): Boolean {
        val header = readExact(input, 2) ?: return false
        if (header[0].toInt() and 0xFF != VERSION) return false
        val methodCount = header[1].toInt() and 0xFF
        if (methodCount == 0) return false
        if (readExact(input, methodCount) == null) return false
        return try {
            output.write(byteArrayOf(VERSION.toByte(), METHOD_NONE.toByte()))
            output.flush()
            true
        } catch (_: IOException) {
            false
        }
    }

    /**
     * A SOCKS5 request for [command] toward [host]:[port].
     *
     * Address-type selection is part of the request, not the caller's job,
     * because the two callers that build a request have opposite reasons to
     * care:
     *  - [SmartDnsResolver], dialing the engine's own listener, has a name and
     *    wants it carried as a name so the engine resolves it inside the tunnel.
     *  - [SmartDnsFront], relaying tun2socks, has an IP that came out of a DNS
     *    answer it already made, and has no name to send.
     *
     * So a parseable IPv4 literal is sent as ATYP 1 and anything else as
     * ATYP 3, which means an address literal and a hostname of the same text
     * produce different bytes on the wire — which is correct, they mean
     * different things.
     *
     * A domain is encoded as ASCII because that is what RFC 1928 specifies and
     * what every server decodes; a UTF-8 name would be silently misread by a
     * server that expects one byte per label character.
     *
     * @param command [CMD_CONNECT] or [CMD_UDP_ASSOCIATE].
     */
    fun request(command: Int, host: String, port: Int): ByteArray {
        val address = ipv4Bytes(host)
        return if (address != null) {
            byteArrayOf(
                VERSION.toByte(),
                command.toByte(),
                0,
                ATYP_IPV4.toByte(),
                address[0],
                address[1],
                address[2],
                address[3],
                portBytes(port)[0],
                portBytes(port)[1],
            )
        } else {
            val name = host.toByteArray(Charsets.US_ASCII)
            // 255 is the largest label length the one-byte field can carry;
            // a longer name cannot be encoded rather than being silently
            // truncated.
            require(name.size <= 255) { "domain too long for SOCKS5: ${name.size}" }
            byteArrayOf(
                VERSION.toByte(),
                command.toByte(),
                0,
                ATYP_DOMAIN.toByte(),
                name.size.toByte(),
            ) + name + portBytes(port)
        }
    }

    /** A CONNECT request, for the common case where the command is constant. */
    fun requestConnect(host: String, port: Int): ByteArray = request(CMD_CONNECT, host, port)

    /**
     * A UDP ASSOCIATE request.
     *
     * The DST.ADDR/DST.PORT of a UDP ASSOCIATE is the client's own address, and
     * the client does not know which ephemeral port it will send from, so
     * `0.0.0.0:0` is what a client that cannot predict it sends — see the
     * callers in `ShardSocksFront.openAssociation` and `TorSocksFront`, which
     * send exactly that.
     *
     * @param clientHost the address datagrams will come from, or `0.0.0.0` for
     *   "unknown at request time".
     * @param clientPort that source port, or 0.
     */
    fun requestUdpAssociate(
        clientHost: String = "0.0.0.0",
        clientPort: Int = 0,
    ): ByteArray = request(CMD_UDP_ASSOCIATE, clientHost, clientPort)

    /**
     * The IPv4 request bytes for a known-good address, without the parse.
     *
     * Takes a four-byte array rather than text because the front-ends already
     * have the bytes — they came out of the TUN's own packet headers — and
     * round-tripping them through a String would be work for no information.
     *
     * @throws IllegalArgumentException if [address] is not exactly four bytes.
     */
    fun requestIpv4(command: Int, address: ByteArray, port: Int): ByteArray {
        require(address.size == 4) { "ipv4 address must be 4 bytes, was ${address.size}" }
        return byteArrayOf(
            VERSION.toByte(),
            command.toByte(),
            0,
            ATYP_IPV4.toByte(),
            address[0],
            address[1],
            address[2],
            address[3],
            portBytes(port)[0],
            portBytes(port)[1],
        )
    }

    /**
     * A successful reply with [boundHost]:[boundPort] as the bound address.
     *
     * The bound address is part of the reply even when the client ignores it,
     * because a client waiting for BND.ADDR would block on a stream that
     * ended early. `0.0.0.0:0` is the conventional "no meaningful address"
     * and is what this app's own listeners send — `ShardSocksFront.replySuccess`
     * and `TorSocksFront.replySuccess` both emit it, and tun2socks reads past it.
     *
     * @param code a REP_* constant, [REP_SUCCESS] by default.
     */
    fun reply(
        code: Int = REP_SUCCESS,
        boundHost: String = "0.0.0.0",
        boundPort: Int = 0,
    ): ByteArray {
        val address = ipv4Bytes(boundHost) ?: byteArrayOf(0, 0, 0, 0)
        return byteArrayOf(
            VERSION.toByte(),
            code.toByte(),
            0,
            ATYP_IPV4.toByte(),
            address[0],
            address[1],
            address[2],
            address[3],
            portBytes(boundPort)[0],
            portBytes(boundPort)[1],
        )
    }

    /**
     * Read a request's DST.ADDR/DST.PORT, given the ATYP already read from the
     * request header.
     *
     * Returns null on a truncated or malformed request — including an ATYP
     * this wire does not speak and a domain length of zero, which carries no
     * usable name — so the caller can reply [REP_ADDRESS_NOT_SUPPORTED] or
     * drop the connection instead of relaying nothing.
     *
     * @param addressType the ATYP byte, unsigned; pass it as read from the
     *   header, not from a signed ByteArray element.
     */
    fun readAddress(input: InputStream, addressType: Int): Target? {
        when (addressType) {
            ATYP_IPV4 -> {
                val address = readExact(input, 4) ?: return null
                return Target.Ipv4(address)
            }
            ATYP_IPV6 -> {
                val address = readExact(input, 16) ?: return null
                return Target.Ipv6(address)
            }
            ATYP_DOMAIN -> {
                val lengthByte = readExact(input, 1) ?: return null
                val length = lengthByte[0].toInt() and 0xFF
                if (length == 0) return null
                val name = readExact(input, length) ?: return null
                return Target.Domain(String(name, Charsets.US_ASCII))
            }
            else -> return null
        }
    }

    /** A destination as [readAddress] parsed it. Sealed so `when` coverage is exhaustive. */
    sealed class Target {
        /** Four address bytes; text form via [ipv4Text]. */
        class Ipv4(val bytes: ByteArray) : Target() {
            override fun equals(other: Any?): Boolean = other is Ipv4 && bytes.contentEquals(other.bytes)
            override fun hashCode(): Int = bytes.contentHashCode()
        }

        /** Sixteen address bytes. Produced by [readAddress], consumed by callers that need it. */
        class Ipv6(val bytes: ByteArray) : Target() {
            override fun equals(other: Any?): Boolean = other is Ipv6 && bytes.contentEquals(other.bytes)
            override fun hashCode(): Int = bytes.contentHashCode()
        }

        /** A hostname, already decoded from ASCII. */
        class Domain(val name: String) : Target() {
            override fun equals(other: Any?): Boolean = other is Domain && name == other.name
            override fun hashCode(): Int = name.hashCode()
        }
    }

    /**
     * Read a full reply — VER, REP, RSV, ATYP, BND.ADDR, BND.PORT — leaving the
     * stream positioned at the payload.
     *
     * Consuming the bound address is not optional bookkeeping: for CONNECT it
     * is the difference between a stream sitting at the first payload byte and
     * one sitting mid-address, and a caller that read only the REP field would
     * feed address bytes to whatever it relays. Returns null when the reply is
     * truncated or not version 5, and a caller must treat null and a non-zero
     * REP the same way — both mean the stream is unusable — but it can tell
     * them apart when the distinction is worth a log line.
     *
     * @return the REP field, unsigned, or -1 when the reply is not usable.
     */
    fun readReply(input: InputStream): Int {
        val header = readExact(input, 4) ?: return -1
        if (header[0].toInt() and 0xFF != VERSION) return -1
        val rep = header[1].toInt() and 0xFF
        // The bound address's shape depends on the ATYP, so it has to be
        // consumed before this returns; a caller that only wanted REP would
        // otherwise find the stream mispositioned.
        when (header[3].toInt() and 0xFF) {
            ATYP_IPV4 -> if (readExact(input, 4 + 2) == null) return -1
            ATYP_IPV6 -> if (readExact(input, 16 + 2) == null) return -1
            ATYP_DOMAIN -> {
                val lengthByte = readExact(input, 1) ?: return -1
                val length = lengthByte[0].toInt() and 0xFF
                if (readExact(input, length + 2) == null) return -1
            }
            else -> return -1
        }
        return rep
    }

    /**
     * The SOCKS5 UDP header that wraps a datagram, RFC 1928 §7.
     *
     * Used on both ends of the same association: the client prepends it before
     * sending a datagram to the relay, and the server prepends it before
     * forwarding one back. The two ends see opposite values in the same fields
     * — a client writes the *destination* it wants reached, a server writes the
     * *source* the datagram came from — which is why the field is named
     * [address] and not source or destination.
     *
     * Only IP literals are built. A UDP datagram has no name to carry and no
     * resolver to hand one to, so ATYP 3 has no meaning here.
     *
     * @param address the four address bytes of the remote endpoint.
     * @param port that endpoint's port.
     * @param payload the datagram itself.
     */
    fun udpHeader(address: ByteArray, port: Int, payload: ByteArray): ByteArray {
        require(address.size == 4 || address.size == 16) {
            "udp address must be 4 or 16 bytes, was ${address.size}"
        }
        val atyp = if (address.size == 4) ATYP_IPV4 else ATYP_IPV6
        val out = ByteArrayOutputStream(6 + address.size + payload.size)
        out.write(0)
        out.write(0)
        out.write(0)
        out.write(atyp)
        out.write(address)
        out.write(portBytes(port))
        out.write(payload)
        return out.toByteArray()
    }

    /**
     * Strip a SOCKS5 UDP header, returning the payload and the address it names.
     *
     * Returns null when [datagram] is truncated, its ATYP is not one this wire
     * builds, or any of RSV/FRAG is non-zero. That last check follows the
     * existing decoders (`ShardSocksFront.decapsulate` rejects FRAG != 0):
     * FRAG is a fragmentation sequence number nothing in this app sends and no
     * peer it talks to uses, and a non-zero one means the datagram is a
     * fragment of something this code cannot reassemble — forwarding it would
     * hand a caller a payload that is really a header fragment.
     *
     * @return the payload and its source address, or null when not usable.
     */
    fun parseUdp(datagram: ByteArray): Udp? {
        // RSV, RSV, FRAG — all three must be zero for a datagram this app will
        // touch. 10 is the smallest legal header: ATYP 1 + 4 addr + 2 port.
        if (datagram.size < 10) return null
        if (datagram[0].toInt() and 0xFF != 0) return null
        if (datagram[1].toInt() and 0xFF != 0) return null
        if (datagram[2].toInt() and 0xFF != 0) return null
        return when (datagram[3].toInt() and 0xFF) {
            ATYP_IPV4 -> {
                val address = datagram.copyOfRange(4, 8)
                Udp(address, u16(datagram, 8), datagram.copyOfRange(10, datagram.size))
            }
            ATYP_IPV6 -> {
                if (datagram.size < 22) return null
                val address = datagram.copyOfRange(4, 20)
                Udp(address, u16(datagram, 20), datagram.copyOfRange(22, datagram.size))
            }
            else -> null
        }
    }

    /** A parsed UDP datagram: the address it names, its port, and its payload. */
    class Udp(
        /**
         * Address bytes — four for ATYP 1, sixteen for ATYP 4.
         *
         * Named `address` and not source or destination because the two ends of
         * an association write opposite things into the same field: a client
         * writes where it wants the datagram to go, a server writes where the
         * datagram came from.
         */
        val address: ByteArray,
        /** The port at [address], big-endian on the wire. */
        val port: Int,
        /** The datagram itself, header stripped. */
        val payload: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean = other is Udp &&
            address.contentEquals(other.address) && port == other.port &&
            payload.contentEquals(other.payload)

        override fun hashCode(): Int {
            var result = address.contentHashCode()
            result = 31 * result + port
            result = 31 * result + payload.contentHashCode()
            return result
        }
    }

    /**
     * Skip a request or reply's bound address on a stream, without allocating
     * for it.
     *
     * Exists because [readReply] and [readAddress] take an [InputStream] while
     * the callers that already have a whole buffer in hand would rather not
     * wrap it just to skip bytes — [DataInputStream] is a wrapper this method
     * keeps out of the callers that do not otherwise need one.
     */
    fun skipAddress(input: DataInputStream) {
        when (val atyp = input.readUnsignedByte()) {
            ATYP_IPV4 -> input.readFully(ByteArray(4 + 2))
            ATYP_IPV6 -> input.readFully(ByteArray(16 + 2))
            ATYP_DOMAIN -> {
                val length = input.readUnsignedByte()
                input.readFully(ByteArray(length + 2))
            }
            else -> throw IOException("unsupported SOCKS5 ATYP: $atyp")
        }
    }
}
