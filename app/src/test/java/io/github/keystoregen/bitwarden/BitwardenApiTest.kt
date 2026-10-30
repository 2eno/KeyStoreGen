package io.github.keystoregen.bitwarden

import io.github.keystoregen.BitwardenExport
import io.github.keystoregen.BitwardenExport.Kdf
import io.github.keystoregen.KeyType
import io.github.keystoregen.KeystoreGenerator
import io.github.keystoregen.SecretNames
import io.github.keystoregen.Subject
import java.net.URLDecoder
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

class BitwardenApiTest {
    private val email = "user@example.com"
    private val password = "correct horse battery staple"

    /** Reference values from Python's hashlib and argon2-cffi. */
    @Test
    fun masterPasswordHashMatchesReference() {
        val pbkdf2 = Kdf(Kdf.PBKDF2, 600_000).masterKey(password, email)
        assertEquals("nfEypS52oCiXbQyehOT45BcIhAJYN/5ltdzSYVXHaWg=", BitwardenExport.masterPasswordHash(pbkdf2, password))
        val argon = Kdf(Kdf.ARGON2ID, 3, 64, 4).masterKey(password, email)
        assertEquals("F5AT2yKzzrLd4OniXAMW5ngYFtDXgAcl+gxyAwyzaRA=", BitwardenExport.masterPasswordHash(argon, password))
    }

    // A fake Bitwarden: prelogin, token and ciphers, checking what the app sends.

    private lateinit var http: FakeHttpServer
    /** Assertion failures inside the server thread would only become a 500, so they are kept here. */
    private var serverFailure: Throwable? = null
    private lateinit var server: BitwardenServer
    private val kdf = Kdf(Kdf.PBKDF2, 5_000)
    private val userKey = ByteArray(64).also(SecureRandom()::nextBytes)
    private var tokenResponse: (Map<String, String>) -> Pair<Int, String> = { 200 to okToken() }
    private var lastForm = emptyMap<String, String>()
    private var lastHeaders = emptyMap<String, String>()
    private var savedCipher: JSONObject? = null

    private fun okToken() = JSONObject()
        .put("access_token", "token-123").put("token_type", "Bearer")
        .put("Key", encryptWithStretched(userKey)).put("Kdf", kdf.type).put("KdfIterations", kdf.iterations)
        .toString()

    /** The vault key as Bitwarden stores it: EncString type 2 under the stretched master key. */
    private fun encryptWithStretched(raw: ByteArray): String {
        val key = BitwardenExport.stretch(kdf.masterKey(password, email))
        val iv = ByteArray(16).also(SecureRandom()::nextBytes)
        val ct = Cipher.getInstance("AES/CBC/PKCS5Padding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.enc, "AES"), IvParameterSpec(iv)); doFinal(raw)
        }
        val mac = Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key.mac, "HmacSHA256")); doFinal(iv + ct) }
        val b = Base64.getEncoder()
        return "2." + b.encodeToString(iv) + "|" + b.encodeToString(ct) + "|" + b.encodeToString(mac)
    }

    @Before
    fun start() {
        http = FakeHttpServer()
        fun <T> checked(block: () -> T): T = try { block() } catch (e: Throwable) { serverFailure = e; throw e }
        http.route("/identity/accounts/prelogin") { ex ->
            checked { assertEquals(email, JSONObject(ex.body).getString("email")) }
            200 to """{"kdf":${kdf.type},"kdfIterations":${kdf.iterations},"kdfMemory":null,"kdfParallelism":null}"""
        }
        http.route("/identity/connect/token") { ex ->
            lastHeaders = ex.headers
            lastForm = ex.body.split('&').associate {
                val (k, v) = it.split('=', limit = 2); k to URLDecoder.decode(v, "UTF-8")
            }
            tokenResponse(lastForm)
        }
        http.route("/api/ciphers") { ex ->
            checked { assertEquals("Bearer token-123", ex.header("Authorization")) }
            savedCipher = JSONObject(ex.body)
            200 to """{"id":"cipher-1","type":2}"""
        }
        http.start()
        val base = "http://127.0.0.1:${http.port}"
        server = BitwardenServer("$base/identity", "$base/api", "test")
    }

    @After
    fun stop() {
        http.stop()
        serverFailure?.let { throw it }
    }

    private fun login(credentials: Credentials = Credentials(email, password)) =
        BitwardenApi.login(server, credentials, "device-1", "Test device")

    @Test
    fun logsInAndSavesAnEncryptedNote() {
        val session = login(Credentials("  User@Example.com ", password))

        assertEquals("password", lastForm["grant_type"])
        assertEquals(email, lastForm["username"])
        val expectedHash = BitwardenExport.masterPasswordHash(kdf.masterKey(password, email), password)
        assertEquals(expectedHash, lastForm["password"])
        assertTrue("the master password itself must never be sent", lastForm.values.none { password in it })
        assertEquals("device-1", lastForm["deviceIdentifier"])
        assertEquals(email, String(Base64.getUrlDecoder().decode(lastHeaders.entries.first { it.key.equals("Auth-Email", true) }.value)))

        val keystore = KeystoreGenerator.generate("release", "store-pass", Subject("App"), 25, KeyType.RSA_4096)
        assertEquals("cipher-1", BitwardenApi.saveKeystore(session, keystore, "App signing key", SecretNames("WEAR_")))

        val cipher = savedCipher!!
        val key = BitwardenExport.Key(userKey.copyOfRange(0, 32), userKey.copyOfRange(32, 64))
        fun dec(field: String) = BitwardenExport.decrypt(field, key)
        assertEquals(2, cipher.getInt("type"))
        assertEquals("App signing key", dec(cipher.getString("name")))
        assertEquals(keystore.base64, dec(cipher.getString("notes")))
        assertTrue("RSA 4096 fits Bitwarden's limit", cipher.getString("notes").length <= BitwardenApi.MAX_ENCRYPTED_FIELD)
        val fields = cipher.getJSONArray("fields")
        val decoded = (0 until fields.length()).associate { i ->
            fields.getJSONObject(i).let { dec(it.getString("name")) to dec(it.getString("value")) }
        }
        assertEquals("store-pass", decoded["WEAR_KEYSTORE_PASSWORD"])
        assertEquals("release", decoded["WEAR_KEYSTORE_ALIAS"])
        assertEquals("store-pass", decoded["WEAR_KEYSTORE_ALIAS_PASSWORD"])
        assertEquals(keystore.sha256, decoded["SHA-256 fingerprint"])
    }

    @Test
    fun wrongMasterPasswordIsCaughtLocallyEvenIfTheServerSaysOk() {
        try {
            login(Credentials(email, "not the password"))
            fail()
        } catch (e: BitwardenException) {
            assertEquals("Wrong master password", e.message)
        }
    }

    @Test
    fun reportsTwoFactorAndSendsTheCode() {
        tokenResponse = { form ->
            if (form["twoFactorToken"] == null) {
                400 to """{"error":"invalid_grant","error_description":"Two factor required.","TwoFactorProviders":["0","1"],"TwoFactorProviders2":{"0":null,"1":{"Email":"u***@example.com"}}}"""
            } else {
                200 to okToken()
            }
        }
        try {
            login()
            fail()
        } catch (c: LoginChallenge.TwoFactor) {
            assertEquals(listOf(0, 1), c.providers.sorted())
            assertEquals("u***@example.com", c.emailHint)
        }
        login(Credentials(email, password, twoFactorProvider = 0, twoFactorCode = "123 456"))
        assertEquals("123456", lastForm["twoFactorToken"])
        assertEquals("0", lastForm["twoFactorProvider"])
    }

    @Test
    fun reportsNewDeviceVerification() {
        tokenResponse = { form ->
            if (form["newDeviceOtp"] == null) {
                400 to """{"error":"invalid_grant","error_description":"New device verification required.","ErrorModel":{"Message":"New device verification required.","Object":"error"}}"""
            } else {
                200 to okToken()
            }
        }
        try {
            login()
            fail()
        } catch (c: LoginChallenge) {
            assertTrue(c === LoginChallenge.NewDevice)
        }
        login(Credentials(email, password, newDeviceCode = "424242"))
        assertEquals("424242", lastForm["newDeviceOtp"])
    }

    @Test
    fun apiKeyLogin() {
        login(Credentials(email, password, clientId = "user.abc", clientSecret = "s3cret"))
        assertEquals("client_credentials", lastForm["grant_type"])
        assertEquals("user.abc", lastForm["client_id"])
        assertEquals("s3cret", lastForm["client_secret"])
        assertTrue(lastForm["password"] == null)
    }

    @Test
    fun serverErrorsAreReadable() {
        tokenResponse = { 400 to """{"error":"invalid_grant","error_description":"invalid_username_or_password","ErrorModel":{"Message":"Username or password is incorrect. Try again."}}""" }
        try {
            login()
            fail()
        } catch (e: BitwardenException) {
            assertEquals("Username or password is incorrect. Try again.", e.message)
        }
    }
}
