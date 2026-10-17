package io.github.keystoregen

import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeystoreGeneratorTest {
    private fun load(generated: SigningKeystore): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            load(ByteArrayInputStream(generated.bytes), generated.password.toCharArray())
        }

    @Test
    fun rsaKeystoreLoadsAndSigns() {
        val generated = KeystoreGenerator.generate(
            "release", "secret-password", Subject("My App", organization = "Me", country = "de"), 30, KeyType.RSA_2048,
        )
        val keyStore = load(generated)
        val key = keyStore.getKey("release", "secret-password".toCharArray()) as PrivateKey
        val cert = keyStore.getCertificate("release") as X509Certificate

        assertEquals("RSA", key.algorithm)
        assertEquals("CN=My App,O=Me,C=DE", cert.subjectX500Principal.name)
        assertEquals(cert.subjectX500Principal, cert.issuerX500Principal)
        assertEquals(3, cert.version)
        cert.checkValidity()
        cert.verify(cert.publicKey)

        val data = "hello".toByteArray()
        val sig = Signature.getInstance("SHA256withRSA").run { initSign(key); update(data); sign() }
        assertTrue(Signature.getInstance("SHA256withRSA").run { initVerify(cert); update(data); verify(sig) })
    }

    @Test
    fun ecKeystoreLoads() {
        val generated = KeystoreGenerator.generate("ec", "secret-password", Subject("EC"), 2080 - 2026, KeyType.EC_P256)
        val cert = load(generated).getCertificate("ec") as X509Certificate
        assertEquals("EC", cert.publicKey.algorithm)
        assertEquals("SHA256withECDSA", cert.sigAlgName)
        // Past 2049 the end date must be a GeneralizedTime, and still parse.
        assertTrue(cert.notAfter.toInstant().toString().startsWith("2080"))
    }

    @Test
    fun fingerprintsHaveTheKeytoolFormat() {
        val generated = KeystoreGenerator.generate("a", "secret-password", Subject("a"), 1, KeyType.EC_P256)
        assertTrue(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}").matches(generated.sha256))
        assertTrue(Regex("([0-9A-F]{2}:){19}[0-9A-F]{2}").matches(generated.sha1))
    }

    @Test
    fun randomPasswordsAvoidLookAlikes() {
        val password = KeystoreGenerator.randomPassword()
        assertEquals(32, password.length)
        assertTrue(password.none { it in "0O1lI" })
    }
}
