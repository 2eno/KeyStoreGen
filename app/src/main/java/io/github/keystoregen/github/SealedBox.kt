package io.github.keystoregen.github

import java.security.SecureRandom
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.math.ec.rfc7748.X25519

/**
 * libsodium's `crypto_box_seal`, which GitHub requires for secret values: an ephemeral
 * X25519 key agrees with the repository's public key, and the value is encrypted with
 * XSalsa20-Poly1305 under a nonce derived from both public keys. Only GitHub can open it.
 */
object SealedBox {
    private const val KEY_BYTES = 32
    private const val MAC_BYTES = 16
    private const val NONCE_BYTES = 24
    private val random = SecureRandom()

    fun seal(message: ByteArray, recipientPublicKey: ByteArray): ByteArray {
        require(recipientPublicKey.size == KEY_BYTES) { "Not an X25519 public key" }
        val ephemeralSecret = ByteArray(KEY_BYTES).also { X25519.generatePrivateKey(random, it) }
        val ephemeralPublic = ByteArray(KEY_BYTES).also { X25519.generatePublicKey(ephemeralSecret, 0, it, 0) }
        val nonce = nonce(ephemeralPublic, recipientPublicKey)
        val box = secretbox(message, nonce, boxKey(ephemeralSecret, recipientPublicKey))
        ephemeralSecret.fill(0)
        return ephemeralPublic + box
    }

    /** The inverse of [seal]; GitHub never needs it, the tests do. */
    fun open(sealed: ByteArray, recipientSecretKey: ByteArray): ByteArray {
        require(sealed.size >= KEY_BYTES + MAC_BYTES) { "Too short" }
        val ephemeralPublic = sealed.copyOfRange(0, KEY_BYTES)
        val recipientPublic = ByteArray(KEY_BYTES).also { X25519.generatePublicKey(recipientSecretKey, 0, it, 0) }
        val key = boxKey(recipientSecretKey, ephemeralPublic)
        val nonce = nonce(ephemeralPublic, recipientPublic)
        val mac = sealed.copyOfRange(KEY_BYTES, KEY_BYTES + MAC_BYTES)
        val ciphertext = sealed.copyOfRange(KEY_BYTES + MAC_BYTES, sealed.size)
        val stream = xsalsa20(key, nonce, KEY_BYTES + ciphertext.size)
        require(java.security.MessageDigest.isEqual(poly1305(stream.copyOf(KEY_BYTES), ciphertext), mac)) { "Bad MAC" }
        return ByteArray(ciphertext.size) { (ciphertext[it].toInt() xor stream[KEY_BYTES + it].toInt()).toByte() }
    }

    /** `crypto_box_beforenm`: HSalsa20 over the X25519 shared secret. */
    private fun boxKey(secretKey: ByteArray, publicKey: ByteArray): ByteArray {
        val shared = ByteArray(KEY_BYTES)
        require(X25519.calculateAgreement(secretKey, 0, publicKey, 0, shared, 0)) { "Invalid public key" }
        return hsalsa20(shared)
    }

    /** `crypto_secretbox`: the first 32 key stream bytes are the Poly1305 key, output is mac ‖ ciphertext. */
    private fun secretbox(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val stream = xsalsa20(key, nonce, KEY_BYTES + message.size)
        val ciphertext = ByteArray(message.size) { (message[it].toInt() xor stream[KEY_BYTES + it].toInt()).toByte() }
        return poly1305(stream.copyOf(KEY_BYTES), ciphertext) + ciphertext
    }

    private fun nonce(ephemeralPublic: ByteArray, recipientPublic: ByteArray): ByteArray {
        val digest = Blake2bDigest(NONCE_BYTES * 8)
        digest.update(ephemeralPublic, 0, ephemeralPublic.size)
        digest.update(recipientPublic, 0, recipientPublic.size)
        return ByteArray(NONCE_BYTES).also { digest.doFinal(it, 0) }
    }

    private fun xsalsa20(key: ByteArray, nonce: ByteArray, length: Int): ByteArray {
        val engine = XSalsa20Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
        return ByteArray(length).also { engine.processBytes(ByteArray(length), 0, length, it, 0) }
    }

    private fun poly1305(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Poly1305()
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        return ByteArray(MAC_BYTES).also { mac.doFinal(it, 0) }
    }

    /**
     * HSalsa20 with an all-zero nonce, as libsodium's crypto_box uses it. Bouncy Castle has
     * it only inside XSalsa20Engine, so here it is: the Salsa20 core without the final
     * addition, keeping words 0, 5, 10, 15, 6, 7, 8, 9.
     */
    private fun hsalsa20(key: ByteArray): ByteArray {
        fun le(b: ByteArray, i: Int) =
            (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8) or
                ((b[i + 2].toInt() and 0xFF) shl 16) or ((b[i + 3].toInt() and 0xFF) shl 24)
        val sigma = "expand 32-byte k".toByteArray(Charsets.US_ASCII)
        val x = IntArray(16)
        x[0] = le(sigma, 0); x[5] = le(sigma, 4); x[10] = le(sigma, 8); x[15] = le(sigma, 12)
        for (i in 0 until 4) {
            x[1 + i] = le(key, i * 4)
            x[11 + i] = le(key, 16 + i * 4)
        }
        // x[6..9], the nonce, stay zero.
        fun qr(a: Int, b: Int, c: Int, d: Int) {
            x[b] = x[b] xor Integer.rotateLeft(x[a] + x[d], 7)
            x[c] = x[c] xor Integer.rotateLeft(x[b] + x[a], 9)
            x[d] = x[d] xor Integer.rotateLeft(x[c] + x[b], 13)
            x[a] = x[a] xor Integer.rotateLeft(x[d] + x[c], 18)
        }
        repeat(10) {
            qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11)
            qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14)
        }
        val out = ByteArray(KEY_BYTES)
        intArrayOf(0, 5, 10, 15, 6, 7, 8, 9).forEachIndexed { i, w ->
            for (j in 0 until 4) out[i * 4 + j] = (x[w] ushr (8 * j)).toByte()
        }
        return out
    }
}
