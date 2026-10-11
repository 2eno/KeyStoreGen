package io.github.keystoregen

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A password-protected Bitwarden JSON export holding one secure note: the notes are the
 * base64 keystore, the custom fields hold the other secrets. Import it at
 * vault.bitwarden.com → Tools → Import data → "Bitwarden (json)".
 *
 * The format follows Bitwarden's own exporter: PBKDF2-SHA256 over the file password with
 * the base64 salt string as salt, HKDF-expanded into an AES-256-CBC key and an
 * HMAC-SHA256 key, every value an "EncString" of type 2.
 */
object BitwardenExport {
    const val KDF_ITERATIONS = 600_000
    const val MIN_PASSWORD_LENGTH = 12

    private const val CIPHER_SECURE_NOTE = 2
    private const val FIELD_TEXT = 0
    private const val FIELD_HIDDEN = 1

    private val random = SecureRandom()
    private val b64 = Base64.getEncoder()

    class Key(val enc: ByteArray, val mac: ByteArray)

    fun plainJson(keystore: GeneratedKeystore, itemName: String, names: SecretNames): String {
        val fields = listOf(
            Triple(names.password, keystore.password, FIELD_HIDDEN),
            Triple(names.alias, keystore.alias, FIELD_TEXT),
            Triple(names.aliasPassword, keystore.password, FIELD_HIDDEN),
            Triple("SHA-256 fingerprint", keystore.sha256, FIELD_TEXT),
            Triple("SHA-1 fingerprint", keystore.sha1, FIELD_TEXT),
            Triple("Valid until", keystore.certificate.notAfter.toInstant().toString(), FIELD_TEXT),
        ).joinToString(",") { (name, value, type) ->
            """{"name":${str(name)},"value":${str(value)},"type":$type,"linkedId":null}"""
        }
        return """{"encrypted":false,"folders":[],"items":[{"id":null,"organizationId":null,""" +
            """"folderId":null,"collectionIds":null,"type":$CIPHER_SECURE_NOTE,"reprompt":0,""" +
            """"name":${str(itemName)},"notes":${str(keystore.base64)},"favorite":false,""" +
            """"secureNote":{"type":0},"fields":[$fields]}]}"""
    }

    fun encryptedJson(plainJson: String, filePassword: String): String {
        val salt = b64.encodeToString(ByteArray(16).also(random::nextBytes))
        val key = deriveKey(filePassword, salt, KDF_ITERATIONS)
        return """{"encrypted":true,"passwordProtected":true,"salt":${str(salt)},"kdfType":0,""" +
            """"kdfIterations":$KDF_ITERATIONS,""" +
            """"encKeyValidation_DO_NOT_EDIT":${str(encrypt(UUID.randomUUID().toString(), key))},""" +
            """"data":${str(encrypt(plainJson, key))}}"""
    }

    fun deriveKey(password: String, salt: String, iterations: Int): Key {
        val master = pbkdf2(password.toByteArray(), salt.toByteArray(), iterations)
        return Key(hkdfExpand(master, "enc"), hkdfExpand(master, "mac"))
    }

    fun encrypt(plain: String, key: Key): String {
        val iv = ByteArray(16).also(random::nextBytes)
        val ct = Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.enc, "AES"), IvParameterSpec(iv))
            doFinal(plain.toByteArray())
        }
        val mac = hmac(key.mac, iv + ct)
        return "2." + b64.encodeToString(iv) + "|" + b64.encodeToString(ct) + "|" + b64.encodeToString(mac)
    }

    fun decrypt(encString: String, key: Key): String {
        require(encString.startsWith("2.")) { "Unsupported EncString type" }
        val (iv, ct, mac) = encString.removePrefix("2.").split('|').map(Base64.getDecoder()::decode)
        require(MessageDigest.isEqual(hmac(key.mac, iv + ct), mac)) { "Bad MAC" }
        return Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key.enc, "AES"), IvParameterSpec(iv))
            String(doFinal(ct))
        }
    }

    /** PBKDF2-HMAC-SHA256 with one output block, which is all a 32-byte key needs. */
    private fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(password, "HmacSHA256")) }
        var u = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
        val out = u.copyOf()
        repeat(iterations - 1) {
            u = mac.doFinal(u)
            for (i in out.indices) out[i] = (out[i].toInt() xor u[i].toInt()).toByte()
        }
        return out
    }

    private fun hkdfExpand(prk: ByteArray, info: String) = hmac(prk, info.toByteArray() + byteArrayOf(1))

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(data)
        }

    private fun str(value: String) = buildString {
        append('"')
        for (c in value) when {
            c == '"' -> append("\\\"")
            c == '\\' -> append("\\\\")
            c < ' ' -> append("\\u%04x".format(c.code))
            else -> append(c)
        }
        append('"')
    }
}
