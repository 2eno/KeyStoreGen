package io.github.keystoregen.github

import java.util.Base64
import org.bouncycastle.math.ec.rfc7748.X25519
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class SealedBoxTest {
    private fun b64(s: String) = Base64.getDecoder().decode(s)

    /** Sealed with libsodium (PyNaCl's SealedBox), so this checks every primitive against it. */
    @Test
    fun opensWhatLibsodiumSealed() {
        val secret = b64("TVF29alaEn2W4SyRRifVwMB+UoCah1icGK9JJQoswRs=")
        val sealed = b64("uU4bSxq19JIPUUUwB0voixqksst6rcVZd/vaded+vg1wz6EY8puRxF7f6zhYgCziPWDuf8DfMeZVS0giKQeWeChI1H4=")
        assertEquals("hello from libsodium", String(SealedBox.open(sealed, secret)))
    }

    @Test
    fun roundTrip() {
        val secret = ByteArray(32).also { X25519.generatePrivateKey(java.security.SecureRandom(), it) }
        val public = ByteArray(32).also { X25519.generatePublicKey(secret, 0, it, 0) }
        val message = ByteArray(5000) { it.toByte() }
        val sealed = SealedBox.seal(message, public)
        assertEquals(32 + 16 + message.size, sealed.size)
        assertArrayEquals(message, SealedBox.open(sealed, secret))
    }

    @Test(expected = IllegalArgumentException::class)
    fun tamperingIsDetected() {
        val secret = b64("TVF29alaEn2W4SyRRifVwMB+UoCah1icGK9JJQoswRs=")
        val sealed = b64("uU4bSxq19JIPUUUwB0voixqksst6rcVZd/vaded+vg1wz6EY8puRxF7f6zhYgCziPWDuf8DfMeZVS0giKQeWeChI1H4=")
        sealed[sealed.size - 1] = (sealed.last() + 1).toByte()
        SealedBox.open(sealed, secret)
    }
}
