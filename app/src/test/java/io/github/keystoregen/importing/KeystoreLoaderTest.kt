package io.github.keystoregen.importing

import io.github.keystoregen.KeyType
import io.github.keystoregen.KeystoreFormat
import io.github.keystoregen.KeystoreGenerator
import io.github.keystoregen.Subject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeystoreLoaderTest {
    private val generated = KeystoreGenerator.generate("upload", "store-pass", Subject("Test"), 25, KeyType.RSA_2048)

    /** A JKS keystore as old keytool versions wrote them, made by the JDK's own provider. */
    private fun jks(keyPassword: String, type: KeyType = KeyType.RSA_2048): Pair<ByteArray, PrivateKey> {
        val source = if (type == KeyType.RSA_2048) generated else
            KeystoreGenerator.generate("upload", "store-pass", Subject("Test"), 25, type)
        val p12 = KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(source.bytes), "store-pass".toCharArray()) }
        val key = p12.getKey("upload", "store-pass".toCharArray()) as PrivateKey
        val jks = KeyStore.getInstance("JKS").apply {
            load(null, null)
            setKeyEntry("upload", key, keyPassword.toCharArray(), arrayOf(p12.getCertificate("upload")))
            setCertificateEntry("someone-else", p12.getCertificate("upload"))
        }
        val bytes = ByteArrayOutputStream().also { jks.store(it, "store-pass".toCharArray()) }.toByteArray()
        return bytes to key
    }

    @Test
    fun opensPkcs12() {
        assertEquals(KeystoreFormat.PKCS12, KeystoreLoader.format(generated.bytes))
        val entries = KeystoreLoader.entries(generated.bytes, "store-pass")
        assertEquals(listOf("upload"), entries.map { it.alias })
        val opened = KeystoreLoader.open(generated.bytes, "store-pass", "upload", "store-pass")
        assertArrayEquals(generated.bytes, opened.bytes)
        assertEquals(generated.sha256, opened.sha256)
        assertEquals("RSA 2048", opened.algorithm)
        assertTrue(opened.imported)
    }

    @Test
    fun opensJksWithSeparateKeyPassword() {
        val (bytes, key) = jks("key-pass")
        assertEquals(KeystoreFormat.JKS, KeystoreLoader.format(bytes))
        // Only the key entry counts; the trusted certificate is skipped.
        assertEquals(listOf("upload"), KeystoreLoader.entries(bytes, "store-pass").map { it.alias })

        val entry = JksReader.read(bytes, "store-pass").single()
        assertArrayEquals(key.encoded, JksReader.privateKey(entry, "key-pass").encoded)

        val opened = KeystoreLoader.open(bytes, "store-pass", "upload", "key-pass")
        assertEquals("key-pass", opened.keyPassword)
        assertEquals(KeystoreFormat.JKS, opened.format)
        assertEquals(generated.sha256, opened.sha256)
        assertArrayEquals(bytes, opened.bytes)
    }

    @Test
    fun opensEcJks() {
        val (bytes, key) = jks("store-pass", KeyType.EC_P256)
        val entry = JksReader.read(bytes, "store-pass").single()
        assertArrayEquals(key.encoded, JksReader.privateKey(entry, "store-pass").encoded)
        assertEquals("EC P-256", KeystoreLoader.open(bytes, "store-pass", "upload", "store-pass").algorithm)
    }

    @Test(expected = WrongPasswordException::class)
    fun wrongJksStorePassword() {
        KeystoreLoader.entries(jks("key-pass").first, "nope")
    }

    @Test(expected = WrongPasswordException::class)
    fun wrongJksKeyPassword() {
        KeystoreLoader.open(jks("key-pass").first, "store-pass", "upload", "store-pass")
    }

    @Test(expected = WrongPasswordException::class)
    fun wrongPkcs12Password() {
        KeystoreLoader.entries(generated.bytes, "nope")
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsOtherFiles() {
        KeystoreLoader.format("{\"items\":[]}".toByteArray())
    }

    @Test
    fun certificateIsTheJdksToo() {
        val (bytes, _) = jks("key-pass")
        val jdk = KeyStore.getInstance("JKS").apply { load(ByteArrayInputStream(bytes), "store-pass".toCharArray()) }
        val cert = jdk.getCertificate("upload") as X509Certificate
        assertEquals(cert, KeystoreLoader.entries(bytes, "store-pass").single().certificate)
    }
}
