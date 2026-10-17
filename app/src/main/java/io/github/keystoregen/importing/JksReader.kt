package io.github.keystoregen.importing

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

/**
 * Reads Java's proprietary JKS keystores, the keytool default before JDK 9. Android
 * ships no JKS provider, so the format is parsed here: big-endian records, each private
 * key protected by Sun's SHA-1 based "KeyProtector" scheme, and a SHA-1 over the whole
 * file keyed with the store password ("Mighty Aphrodite").
 */
object JksReader {
    private const val MAGIC = 0xFEEDFEED.toInt()
    private const val PRIVATE_KEY = 1
    private const val TRUSTED_CERT = 2
    private const val KEY_PROTECTOR_OID = "1.3.6.1.4.1.42.2.17.1.1"

    class Entry(val alias: String, val protectedKey: ByteArray, val chain: List<X509Certificate>)

    fun isJks(bytes: ByteArray) = bytes.size >= 4 && DataInputStream(ByteArrayInputStream(bytes)).readInt() == MAGIC

    /** The key entries, after checking the file's integrity against [storePassword]. */
    fun read(bytes: ByteArray, storePassword: String): List<Entry> {
        require(bytes.size > 20 && isJks(bytes)) { "Not a JKS keystore" }
        val body = bytes.copyOfRange(0, bytes.size - 20)
        val expected = bytes.copyOfRange(bytes.size - 20, bytes.size)
        val digest = MessageDigest.getInstance("SHA-1").run {
            update(passwordBytes(storePassword))
            update("Mighty Aphrodite".toByteArray(Charsets.UTF_8))
            digest(body)
        }
        if (!MessageDigest.isEqual(digest, expected)) throw WrongPasswordException("Wrong keystore password")

        val input = DataInputStream(ByteArrayInputStream(body))
        input.readInt() // magic
        val version = input.readInt()
        require(version == 1 || version == 2) { "Unsupported JKS version $version" }
        val certificates = CertificateFactory.getInstance("X.509")
        fun readCertificate(): X509Certificate {
            if (version == 2) input.readUTF() // certificate type, always X.509
            val encoded = ByteArray(input.readInt()).also(input::readFully)
            return certificates.generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        }

        val entries = mutableListOf<Entry>()
        repeat(input.readInt()) {
            when (val tag = input.readInt()) {
                PRIVATE_KEY -> {
                    val alias = input.readUTF()
                    input.readLong() // creation date
                    val key = ByteArray(input.readInt()).also(input::readFully)
                    val chain = List(input.readInt()) { readCertificate() }
                    entries += Entry(alias, key, chain)
                }
                TRUSTED_CERT -> {
                    input.readUTF()
                    input.readLong()
                    readCertificate()
                }
                else -> throw IllegalArgumentException("Unsupported JKS entry type $tag")
            }
        }
        return entries
    }

    /** Recovers the PKCS#8 private key of [entry], typed after its certificate's public key. */
    fun privateKey(entry: Entry, keyPassword: String): PrivateKey {
        // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        val info = DerReader(entry.protectedKey).sequence()
        val algorithm = info.sequence()
        require(algorithm.oid() == KEY_PROTECTOR_OID) { "Unsupported key protection" }
        val data = info.octetString()

        val password = passwordBytes(keyPassword)
        val salt = data.copyOfRange(0, 20)
        val encrypted = data.copyOfRange(20, data.size - 20)
        val check = data.copyOfRange(data.size - 20, data.size)

        val sha1 = MessageDigest.getInstance("SHA-1")
        val plain = ByteArray(encrypted.size)
        var block = salt
        var offset = 0
        while (offset < encrypted.size) {
            sha1.update(password)
            block = sha1.digest(block)
            for (i in block.indices) {
                if (offset + i >= encrypted.size) break
                plain[offset + i] = (encrypted[offset + i].toInt() xor block[i].toInt()).toByte()
            }
            offset += block.size
        }
        sha1.update(password)
        if (!MessageDigest.isEqual(sha1.digest(plain), check)) throw WrongPasswordException("Wrong key password")

        val publicKey = entry.chain.firstOrNull()?.publicKey ?: throw IllegalArgumentException("The key has no certificate")
        return KeyFactory.getInstance(publicKey.algorithm).generatePrivate(PKCS8EncodedKeySpec(plain))
    }

    /** Java chars as UTF-16BE, without a byte order mark. */
    private fun passwordBytes(password: String) = ByteArray(password.length * 2).also {
        password.forEachIndexed { i, c ->
            it[2 * i] = (c.code shr 8).toByte()
            it[2 * i + 1] = c.code.toByte()
        }
    }
}

/** A minimal DER reader for the one structure JKS keys are wrapped in. */
internal class DerReader(private val bytes: ByteArray, private var pos: Int = 0, private val end: Int = bytes.size) {
    private fun element(expectedTag: Int): IntRange {
        require(pos < end && (bytes[pos].toInt() and 0xFF) == expectedTag) { "Malformed key data" }
        pos++
        var length = bytes[pos++].toInt() and 0xFF
        if (length and 0x80 != 0) {
            val count = length and 0x7F
            length = 0
            repeat(count) { length = (length shl 8) or (bytes[pos++].toInt() and 0xFF) }
        }
        val start = pos
        pos += length
        require(pos <= end) { "Malformed key data" }
        return start until pos
    }

    fun sequence(): DerReader = element(0x30).let { DerReader(bytes, it.first, it.last + 1) }
    fun octetString(): ByteArray = element(0x04).let { bytes.copyOfRange(it.first, it.last + 1) }

    fun oid(): String {
        val range = element(0x06)
        val arcs = mutableListOf<Long>()
        var value = 0L
        for (i in range) {
            val b = bytes[i].toInt() and 0xFF
            value = (value shl 7) or (b and 0x7F).toLong()
            if (b and 0x80 == 0) {
                if (arcs.isEmpty()) {
                    arcs += minOf(value / 40, 2)
                    arcs += value - arcs[0] * 40
                } else {
                    arcs += value
                }
                value = 0
            }
        }
        return arcs.joinToString(".")
    }
}
