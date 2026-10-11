package io.github.keystoregen

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.time.ZoneOffset
import java.time.ZonedDateTime

enum class KeyType(val label: String, val detail: String) {
    RSA_4096("RSA 4096", "Recommended, same as keytool -keysize 4096"),
    RSA_3072("RSA 3072", "Smaller signatures, still strong"),
    RSA_2048("RSA 2048", "keytool's default size"),
    EC_P256("EC P-256", "Small and fast; not accepted by some older tools"),
}

/** The subject of the self-signed certificate. Only the common name is required. */
data class Subject(
    val commonName: String,
    val organizationalUnit: String = "",
    val organization: String = "",
    val locality: String = "",
    val state: String = "",
    val country: String = "",
) {
    /** RFC 4514 style, the way keytool prints it: CN first. */
    val distinguishedName: String
        get() = listOf(
            "CN" to commonName, "OU" to organizationalUnit, "O" to organization,
            "L" to locality, "ST" to state, "C" to country,
        ).filter { it.second.isNotBlank() }.joinToString(", ") { "${it.first}=${it.second}" }
}

class GeneratedKeystore(
    val bytes: ByteArray,
    val alias: String,
    val password: String,
    val keyType: KeyType,
    val certificate: X509Certificate,
) {
    val base64: String get() = java.util.Base64.getEncoder().encodeToString(bytes)
    val sha256: String get() = fingerprint("SHA-256")
    val sha1: String get() = fingerprint("SHA-1")

    private fun fingerprint(algorithm: String): String =
        MessageDigest.getInstance(algorithm).digest(certificate.encoded)
            .joinToString(":") { "%02X".format(it) }
}

object KeystoreGenerator {
    private const val PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    private val random = SecureRandom()

    /** Without look-alike characters (0/O, 1/l/I), so it can be typed off a screen. */
    fun randomPassword(length: Int = 32): String =
        String(CharArray(length) { PASSWORD_ALPHABET[random.nextInt(PASSWORD_ALPHABET.length)] })

    /**
     * The equivalent of `keytool -genkeypair -storetype PKCS12`: a new key pair and a
     * self-signed certificate in a PKCS#12 keystore. Keystore and key share one password,
     * as PKCS#12 keystores require.
     */
    fun generate(
        alias: String,
        password: String,
        subject: Subject,
        validityYears: Int,
        keyType: KeyType = KeyType.RSA_4096,
    ): GeneratedKeystore {
        require(alias.isNotBlank()) { "The alias is empty" }
        require(password.length >= 6) { "The password needs at least 6 characters" }
        require(subject.commonName.isNotBlank()) { "The certificate name is empty" }
        require(validityYears in 1..1000) { "The validity must be 1 to 1000 years" }

        val (generator, signatureAlgorithm, algorithmId) = when (keyType) {
            KeyType.EC_P256 -> Triple(
                KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) },
                "SHA256withECDSA",
                Der.seq(Der.oid("1.2.840.10045.4.3.2")),
            )
            else -> Triple(
                KeyPairGenerator.getInstance("RSA").apply {
                    initialize(keyType.name.removePrefix("RSA_").toInt(), random)
                },
                "SHA256withRSA",
                Der.seq(Der.oid("1.2.840.113549.1.1.11"), Der.NULL),
            )
        }
        val keyPair = generator.generateKeyPair()

        val now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0)
        val name = Der.name(subject.toAttributes())
        val tbs = Der.seq(
            Der.explicit(0, Der.integer(BigInteger.valueOf(2))), // v3
            Der.integer(BigInteger(63, random).add(BigInteger.ONE)),
            algorithmId,
            name,
            Der.seq(Der.time(now), Der.time(now.plusYears(validityYears.toLong()))),
            name,
            keyPair.public.encoded,
        )
        val signature = Signature.getInstance(signatureAlgorithm).run {
            initSign(keyPair.private)
            update(tbs)
            sign()
        }
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(Der.seq(tbs, algorithmId, Der.bitString(signature))))
            as X509Certificate
        certificate.verify(keyPair.public)

        val chars = password.toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry(alias, keyPair.private, chars, arrayOf(certificate))
        }
        val bytes = ByteArrayOutputStream().also { keyStore.store(it, chars) }.toByteArray()
        return GeneratedKeystore(bytes, alias, password, keyType, certificate)
    }

    private fun Subject.toAttributes(): List<Pair<String, ByteArray>> = buildList {
        // Most significant first, which is the reverse of how keytool prints it.
        if (country.isNotBlank()) add("2.5.4.6" to Der.printable(country.uppercase()))
        if (state.isNotBlank()) add("2.5.4.8" to Der.utf8(state))
        if (locality.isNotBlank()) add("2.5.4.7" to Der.utf8(locality))
        if (organization.isNotBlank()) add("2.5.4.10" to Der.utf8(organization))
        if (organizationalUnit.isNotBlank()) add("2.5.4.11" to Der.utf8(organizationalUnit))
        add("2.5.4.3" to Der.utf8(commonName))
    }
}
