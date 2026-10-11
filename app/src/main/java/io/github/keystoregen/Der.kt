package io.github.keystoregen

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * Just enough DER to build a self-signed X.509 certificate. Android ships no
 * certificate builder, and pulling in Bouncy Castle for one certificate is a
 * lot of APK for very little.
 */
internal object Der {
    val NULL = byteArrayOf(0x05, 0x00)

    fun tlv(tag: Int, content: ByteArray): ByteArray {
        val n = content.size
        val header = when {
            n < 0x80 -> byteArrayOf(tag.toByte(), n.toByte())
            n < 0x100 -> byteArrayOf(tag.toByte(), 0x81.toByte(), n.toByte())
            n < 0x10000 -> byteArrayOf(tag.toByte(), 0x82.toByte(), (n shr 8).toByte(), n.toByte())
            else -> byteArrayOf(tag.toByte(), 0x83.toByte(), (n shr 16).toByte(), (n shr 8).toByte(), n.toByte())
        }
        return header + content
    }

    fun seq(vararg parts: ByteArray) = tlv(0x30, concat(parts))
    fun set(vararg parts: ByteArray) = tlv(0x31, concat(parts))
    fun explicit(tag: Int, inner: ByteArray) = tlv(0xA0 or tag, inner)
    fun integer(value: BigInteger) = tlv(0x02, value.toByteArray())
    fun bitString(bytes: ByteArray) = tlv(0x03, byteArrayOf(0) + bytes)
    fun utf8(value: String) = tlv(0x0C, value.toByteArray(Charsets.UTF_8))
    fun printable(value: String) = tlv(0x13, value.toByteArray(Charsets.US_ASCII))

    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map(String::toLong)
        val out = ByteArrayOutputStream()
        out.write((arcs[0] * 40 + arcs[1]).toInt())
        for (arc in arcs.drop(2)) {
            var septets = listOf((arc and 0x7F).toInt())
            var rest = arc shr 7
            while (rest > 0) {
                septets = listOf(((rest and 0x7F) or 0x80).toInt()) + septets
                rest = rest shr 7
            }
            septets.forEach(out::write)
        }
        return tlv(0x06, out.toByteArray())
    }

    /** An X.500 name with one attribute per RDN, in the order given (most significant first). */
    fun name(attributes: List<Pair<String, ByteArray>>): ByteArray =
        seq(*attributes.map { (oid, value) -> set(seq(oid(oid), value)) }.toTypedArray())

    /** RFC 5280: UTCTime through 2049, GeneralizedTime from 2050. */
    fun time(time: ZonedDateTime): ByteArray =
        if (time.year < 2050) {
            tlv(0x17, time.format(DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")).toByteArray())
        } else {
            tlv(0x18, time.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")).toByteArray())
        }

    private fun concat(parts: Array<out ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        parts.forEach(out::write)
        return out.toByteArray()
    }
}
