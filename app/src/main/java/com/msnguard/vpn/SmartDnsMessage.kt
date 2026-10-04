package com.msnguard.vpn

import kotlin.random.Random

object SmartDnsMessage {

    fun transactionId(packet: ByteArray): Int {
        if (packet.size < 2) return -1
        return ((packet[0].toInt() and 0xFF) shl 8) or (packet[1].toInt() and 0xFF)
    }

    fun isResponse(packet: ByteArray): Boolean {
        if (packet.size < 3) return false
        return (packet[2].toInt() and 0x80) != 0
    }

    fun isTruncated(packet: ByteArray): Boolean {
        if (packet.size < 3) return false
        return (packet[2].toInt() and 0x02) != 0
    }

    fun rcode(packet: ByteArray): Int {
        if (packet.size < 4) return -1
        return packet[3].toInt() and 0x0F
    }

    fun questionType(packet: ByteArray): Int {
        if (packet.size < 12) return -1
        val pos = skipName(packet, 12)
        if (pos == -1 || pos + 4 > packet.size) return -1
        return ((packet[pos].toInt() and 0xFF) shl 8) or (packet[pos + 1].toInt() and 0xFF)
    }

    fun skipName(packet: ByteArray, pos: Int): Int {
        var p = pos
        var jumps = 0
        while (true) {
            if (p >= packet.size) return -1
            val len = packet[p].toInt() and 0xFF
            if (len and 0xC0 == 0xC0) {
                if (p + 1 >= packet.size) return -1
                return p + 2
            }
            if (len == 0) return p + 1
            if (len and 0xC0 != 0) return -1
            if (len > 63) return -1
            p += 1
            if (p + len > packet.size) return -1
            if (++jumps > 128) return -1
            p += len
        }
    }

    fun questionEnd(packet: ByteArray): Int {
        if (packet.size < 12) return -1
        val qdCount = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        if (qdCount == 0) return -1
        val nameEnd = skipName(packet, 12)
        if (nameEnd == -1) return -1
        if (nameEnd + 4 > packet.size) return -1
        return nameEnd + 4
    }

    fun buildQuery(name: String, qtype: Int = 1, id: Int = Random.nextInt(0, 65536)): ByteArray {
        val labels = name.split('.').filter { it.isNotEmpty() }
        var size = 12
        for (l in labels) size += 1 + l.length
        size += 1 + 4
        val out = ByteArray(size)
        out[0] = (id shr 8).toByte()
        out[1] = (id and 0xFF).toByte()
        out[2] = 0x01
        out[3] = 0x00
        out[4] = 0x00
        out[5] = 0x01
        // QDCOUNT=1 already, rest 0
        var p = 12
        for (label in labels) {
            val len = label.length.coerceAtMost(63)
            out[p++] = len.toByte()
            for (c in label) out[p++] = c.code.toByte()
        }
        out[p++] = 0
        out[p++] = (qtype shr 8).toByte()
        out[p++] = (qtype and 0xFF).toByte()
        out[p++] = 0x00
        out[p] = 0x01
        return out
    }

    fun nodataResponse(query: ByteArray): ByteArray = buildResponse(query, rcode = 0, anCount = 0)

    fun servfailResponse(query: ByteArray): ByteArray = buildResponse(query, rcode = 2, anCount = 0)

    fun answerIpv4s(packet: ByteArray): List<String> {
        if (packet.size < 12) return emptyList()
        val qd = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        val an = ((packet[6].toInt() and 0xFF) shl 8) or (packet[7].toInt() and 0xFF)
        var pos = 12
        repeat(qd) {
            val n = skipName(packet, pos)
            if (n == -1 || n + 4 > packet.size) return emptyList()
            pos = n + 4
        }
        val out = mutableListOf<String>()
        repeat(an) {
            val n = skipName(packet, pos)
            if (n == -1 || n + 10 > packet.size) return out
            val rtype = ((packet[n].toInt() and 0xFF) shl 8) or (packet[n + 1].toInt() and 0xFF)
            val rdLen = ((packet[n + 8].toInt() and 0xFF) shl 8) or (packet[n + 9].toInt() and 0xFF)
            val rdata = n + 10
            if (rdata + rdLen > packet.size) return out
            if (rtype == 1 && rdLen == 4) {
                val a = packet[rdata].toInt() and 0xFF
                val b = packet[rdata + 1].toInt() and 0xFF
                val c = packet[rdata + 2].toInt() and 0xFF
                val d = packet[rdata + 3].toInt() and 0xFF
                out += "$a.$b.$c.$d"
            }
            pos = rdata + rdLen
        }
        return out
    }

    private fun buildResponse(query: ByteArray, rcode: Int, anCount: Int): ByteArray {
        if (query.size < 12) {
            val id = if (query.size >= 2) transactionId(query).coerceAtLeast(0) else 0
            val hdr = ByteArray(12)
            hdr[0] = (id shr 8).toByte()
            hdr[1] = (id and 0xFF).toByte()
            hdr[2] = 0x81.toByte()
            hdr[3] = (0x80 or (rcode and 0x0F)).toByte()
            return hdr
        }
        val qEnd = questionEnd(query)
        if (qEnd == -1) {
            val out = ByteArray(12)
            if (query.size >= 2) { out[0] = query[0]; out[1] = query[1] }
            out[2] = 0x81.toByte()
            out[3] = (0x80 or (rcode and 0x0F)).toByte()
            out[4] = 0x00; out[5] = 0x01
            return out
        }
        val out = ByteArray(qEnd)
        out[0] = query[0]
        out[1] = query[1]
        val rd = query[2].toInt() and 0x01
        out[2] = (0x80 or rd).toByte()
        out[3] = (0x80 or (rcode and 0x0F)).toByte()
        out[4] = 0x00; out[5] = 0x01
        out[6] = (anCount shr 8).toByte()
        out[7] = (anCount and 0xFF).toByte()
        out[8] = 0x00; out[9] = 0x00
        out[10] = 0x00; out[11] = 0x00
        query.copyInto(out, 12, 12, qEnd)
        return out
    }
}
