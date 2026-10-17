package io.github.keystoregen.importing

import io.github.keystoregen.KeystoreFormat
import io.github.keystoregen.SigningKeystore
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate

class WrongPasswordException(message: String) : IllegalArgumentException(message)

/** A key entry found in a keystore, before its key password is known. */
data class KeyEntry(val alias: String, val certificate: X509Certificate)

/**
 * Opens existing keystores: PKCS#12 (keytool's default since JDK 9, and what this app
 * writes) through the platform, JKS through [JksReader]. The file is kept byte for byte,
 * so CI gets exactly the keystore the user already has.
 */
object KeystoreLoader {
    fun format(bytes: ByteArray): KeystoreFormat = when {
        JksReader.isJks(bytes) -> KeystoreFormat.JKS
        bytes.size >= 4 && bytes[0] == 0xCE.toByte() && bytes[1] == 0xCE.toByte() ->
            throw IllegalArgumentException("JCEKS keystores aren't supported. Convert it with: keytool -importkeystore -srcstoretype JCEKS -deststoretype PKCS12")
        bytes.isNotEmpty() && bytes[0] == 0x30.toByte() -> KeystoreFormat.PKCS12
        else -> throw IllegalArgumentException("This file isn't a keystore (.jks, .p12, .keystore)")
    }

    /** The key entries of the keystore; throws [WrongPasswordException] for a wrong store password. */
    fun entries(bytes: ByteArray, storePassword: String): List<KeyEntry> = when (format(bytes)) {
        KeystoreFormat.JKS -> JksReader.read(bytes, storePassword).mapNotNull { e ->
            e.chain.firstOrNull()?.let { KeyEntry(e.alias, it) }
        }
        KeystoreFormat.PKCS12 -> {
            val keyStore = pkcs12(bytes, storePassword)
            keyStore.aliases().toList().filter(keyStore::isKeyEntry).mapNotNull { alias ->
                (keyStore.getCertificate(alias) as? X509Certificate)?.let { KeyEntry(alias, it) }
            }
        }
    }.also { require(it.isNotEmpty()) { "The keystore holds no private key" } }

    /** Checks that [keyPassword] opens [alias], and returns the keystore ready for CI. */
    fun open(bytes: ByteArray, storePassword: String, alias: String, keyPassword: String): SigningKeystore =
        when (val format = format(bytes)) {
            KeystoreFormat.JKS -> {
                val entry = JksReader.read(bytes, storePassword).first { it.alias == alias }
                JksReader.privateKey(entry, keyPassword)
                SigningKeystore(bytes, alias, storePassword, keyPassword, entry.chain.first(), format, imported = true)
            }
            KeystoreFormat.PKCS12 -> {
                val keyStore = pkcs12(bytes, storePassword)
                try {
                    requireNotNull(keyStore.getKey(alias, keyPassword.toCharArray())) { "No key named $alias" }
                } catch (e: UnrecoverableKeyException) {
                    throw WrongPasswordException("Wrong key password")
                }
                val certificate = keyStore.getCertificate(alias) as X509Certificate
                SigningKeystore(bytes, alias, storePassword, keyPassword, certificate, format, imported = true)
            }
        }

    private fun pkcs12(bytes: ByteArray, password: String): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            try {
                load(ByteArrayInputStream(bytes), password.toCharArray())
            } catch (e: IOException) {
                // Both the JDK and Android report a failed MAC as an IOException.
                if (e.cause is UnrecoverableKeyException || e.message?.contains("password", ignoreCase = true) == true ||
                    e.message?.contains("mac", ignoreCase = true) == true
                ) {
                    throw WrongPasswordException("Wrong keystore password")
                }
                throw e
            }
        }
}
