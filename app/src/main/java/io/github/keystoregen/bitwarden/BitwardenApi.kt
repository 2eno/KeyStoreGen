package io.github.keystoregen.bitwarden

import io.github.keystoregen.BitwardenExport
import io.github.keystoregen.BitwardenExport.Kdf
import io.github.keystoregen.SecretNames
import io.github.keystoregen.SigningKeystore
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

/** Bitwarden cloud regions, or a self-hosted server by its base URL. */
data class BitwardenServer(val identity: String, val api: String, val label: String) {
    companion object {
        val US = BitwardenServer("https://identity.bitwarden.com", "https://api.bitwarden.com", "bitwarden.com")
        val EU = BitwardenServer("https://identity.bitwarden.eu", "https://api.bitwarden.eu", "bitwarden.eu")

        fun selfHosted(base: String): BitwardenServer {
            val url = base.trim().trimEnd('/').let { if ("://" in it) it else "https://$it" }
            require(url.startsWith("https://")) { "The server must use https" }
            return BitwardenServer("$url/identity", "$url/api", url.removePrefix("https://"))
        }
    }
}

class BitwardenException(message: String, val status: Int = 0) : IOException(message)

/** What the server wants before it hands out a token. */
sealed class LoginChallenge : Exception() {
    /** Two-step login; [providers] are Bitwarden's provider ids, 0 authenticator app, 1 email. */
    class TwoFactor(val providers: List<Int>, val emailHint: String?) : LoginChallenge()

    /** A first login from this device: Bitwarden mailed a code to the account's address. */
    object NewDevice : LoginChallenge()
}

/** A logged-in, unlocked vault: the access token and the key that encrypts items. */
class BitwardenSession(
    val server: BitwardenServer,
    val email: String,
    val accessToken: String,
    val userKey: BitwardenExport.Key,
)

/** Email/password or personal API key credentials, plus answers to [LoginChallenge]s. */
data class Credentials(
    val email: String,
    val masterPassword: String,
    val clientId: String? = null,
    val clientSecret: String? = null,
    val twoFactorProvider: Int? = null,
    val twoFactorCode: String? = null,
    val newDeviceCode: String? = null,
)

/**
 * The parts of Bitwarden's identity and API servers the app needs: log in the way the
 * official clients do, unlock the vault key locally, and create one secure note. The
 * master password never leaves the phone; the server only sees a hash of the master key.
 */
object BitwardenApi {
    /** Bitwarden encrypts at most 10,000 characters per field; longer notes are rejected. */
    const val MAX_ENCRYPTED_FIELD = 10_000

    private const val DEVICE_TYPE_ANDROID = 0
    private const val CIPHER_SECURE_NOTE = 2
    private const val FIELD_TEXT = 0
    private const val FIELD_HIDDEN = 1

    fun kdf(server: BitwardenServer, email: String): Kdf {
        val json = JSONObject(
            post("${server.identity}/accounts/prelogin", JSONObject().put("email", email).toString(), "application/json"),
        )
        return json.kdf() ?: Kdf(Kdf.PBKDF2, 600_000)
    }

    /**
     * Logs in and unlocks the vault. Throws a [LoginChallenge] when the server asks for a
     * second factor or a new-device code; call again with the answer in [credentials].
     */
    fun login(server: BitwardenServer, credentials: Credentials, deviceId: String, deviceName: String): BitwardenSession {
        val email = credentials.email.trim().lowercase()
        val apiKey = credentials.clientId != null
        var kdf = kdf(server, email)
        val masterKey = kdf.masterKey(credentials.masterPassword, email)

        val form = mutableListOf(
            "scope" to if (apiKey) "api" else "api offline_access",
            "client_id" to (credentials.clientId ?: "mobile"),
            "deviceType" to DEVICE_TYPE_ANDROID.toString(),
            "deviceIdentifier" to deviceId,
            "deviceName" to deviceName,
        )
        if (apiKey) {
            form += "grant_type" to "client_credentials"
            form += "client_secret" to credentials.clientSecret.orEmpty()
        } else {
            form += "grant_type" to "password"
            form += "username" to email
            form += "password" to BitwardenExport.masterPasswordHash(masterKey, credentials.masterPassword)
        }
        credentials.twoFactorCode?.let {
            form += "twoFactorToken" to it.filterNot(Char::isWhitespace)
            form += "twoFactorProvider" to (credentials.twoFactorProvider ?: 0).toString()
            form += "twoFactorRemember" to "0"
        }
        credentials.newDeviceCode?.let { form += "newDeviceOtp" to it.filterNot(Char::isWhitespace) }

        val headers = if (apiKey) emptyMap() else mapOf(
            // Required by the identity server for password logins.
            "Auth-Email" to Base64.getUrlEncoder().withoutPadding().encodeToString(email.toByteArray()),
        )
        val (status, body) = request("POST", "${server.identity}/connect/token", formBody(form), "application/x-www-form-urlencoded", headers)
        val json = runCatching { JSONObject(body) }.getOrElse { throw BitwardenException("Bitwarden error $status", status) }
        if (status !in 200..299) throw loginError(json, status)

        // An API key login returns the account's KDF too; it wins over prelogin's answer.
        val masterKeyForVault = json.kdf()?.takeIf { it != kdf }?.let {
            kdf = it
            it.masterKey(credentials.masterPassword, email)
        } ?: masterKey
        val accessToken = json.getString("access_token")
        val encryptedUserKey = json.string("Key", "key") ?: profileKey(server, accessToken)
            ?: throw BitwardenException("This account has no master password (SSO or passkey only), which the app needs to unlock the vault.")
        val userKey = try {
            val raw = BitwardenExport.decryptBytes(encryptedUserKey, BitwardenExport.stretch(masterKeyForVault), masterKeyForVault)
            require(raw.size == 64) { "Unexpected vault key" }
            BitwardenExport.Key(raw.copyOfRange(0, 32), raw.copyOfRange(32, 64))
        } catch (e: IllegalArgumentException) {
            throw BitwardenException("Wrong master password")
        }
        return BitwardenSession(server, email, accessToken, userKey)
    }

    /** The encrypted vault key from the profile, for logins whose token response leaves it out. */
    private fun profileKey(server: BitwardenServer, accessToken: String): String? {
        val (status, body) = request("GET", "${server.api}/accounts/profile", null, null, mapOf("Authorization" to "Bearer $accessToken"))
        if (status !in 200..299) return null
        return runCatching { JSONObject(body).string("key", "Key") }.getOrNull()
    }

    /** Asks Bitwarden to mail the two-step login code, for accounts using email as second factor. */
    fun sendEmailCode(server: BitwardenServer, email: String, masterPassword: String, deviceId: String) {
        val normalized = email.trim().lowercase()
        val masterKey = kdf(server, normalized).masterKey(masterPassword, normalized)
        val body = JSONObject()
            .put("email", normalized)
            .put("masterPasswordHash", BitwardenExport.masterPasswordHash(masterKey, masterPassword))
            .put("deviceIdentifier", deviceId)
        post("${server.api}/two-factor/send-email-login", body.toString(), "application/json")
    }

    /** The keystore as a secure note, the same layout as the export file. Returns the new item's id. */
    fun saveKeystore(session: BitwardenSession, keystore: SigningKeystore, itemName: String, names: SecretNames): String {
        val key = session.userKey
        fun enc(value: String) = BitwardenExport.encrypt(value, key)
        val notes = enc(keystore.base64)
        if (notes.length > MAX_ENCRYPTED_FIELD) {
            throw BitwardenException("This keystore is too big for a Bitwarden note (${keystore.bytes.size} bytes). Save the file instead.")
        }
        val fields = JSONArray()
        listOf(
            Triple(names.password, keystore.password, FIELD_HIDDEN),
            Triple(names.alias, keystore.alias, FIELD_TEXT),
            Triple(names.aliasPassword, keystore.keyPassword, FIELD_HIDDEN),
            Triple("SHA-256 fingerprint", keystore.sha256, FIELD_TEXT),
            Triple("SHA-1 fingerprint", keystore.sha1, FIELD_TEXT),
            Triple("Valid until", keystore.certificate.notAfter.toInstant().toString(), FIELD_TEXT),
        ).forEach { (name, value, type) ->
            fields.put(JSONObject().put("type", type).put("name", enc(name)).put("value", enc(value)))
        }
        val cipher = JSONObject()
            .put("type", CIPHER_SECURE_NOTE)
            .put("name", enc(itemName))
            .put("notes", notes)
            .put("secureNote", JSONObject().put("type", 0))
            .put("fields", fields)
            .put("favorite", false)
            .put("reprompt", 0)
            .put("folderId", JSONObject.NULL)
            .put("organizationId", JSONObject.NULL)
        val (status, body) = request(
            "POST", "${session.server.api}/ciphers", cipher.toString(), "application/json",
            mapOf("Authorization" to "Bearer ${session.accessToken}"),
        )
        if (status == 401) throw BitwardenException("The Bitwarden session expired. Sign in again.", status)
        if (status !in 200..299) throw BitwardenException(apiError(body, status), status)
        return runCatching { JSONObject(body).string("id", "Id") }.getOrNull().orEmpty()
    }

    private fun loginError(json: JSONObject, status: Int): Exception {
        json.optJSONObject("TwoFactorProviders2")?.let { providers ->
            val ids = providers.keys().asSequence().mapNotNull { it.toIntOrNull() }.toList()
            val emailHint = providers.optJSONObject("1")?.optString("Email")?.ifEmpty { null }
            return LoginChallenge.TwoFactor(ids, emailHint)
        }
        val description = json.optString("error_description")
        val message = json.optJSONObject("ErrorModel")?.optString("Message").orEmpty()
        if ("new device verification" in (description + message).lowercase()) return LoginChallenge.NewDevice
        if (json.has("HCaptcha_SiteKey")) {
            return BitwardenException("Bitwarden wants a captcha for this login, which the app can't show. Sign in with your personal API key instead.")
        }
        return BitwardenException(
            when {
                message.isNotEmpty() -> message
                description == "invalid_username_or_password" -> "Wrong email or master password"
                json.optString("error") == "invalid_client" -> "Wrong API key"
                description.isNotEmpty() -> description
                else -> "Bitwarden error $status"
            },
            status,
        )
    }

    private fun apiError(body: String, status: Int): String {
        val json = runCatching { JSONObject(body) }.getOrNull()
        val message = json?.string("message", "Message")
        val details = json?.optJSONObject("validationErrors") ?: json?.optJSONObject("ValidationErrors")
        val first = details?.keys()?.asSequence()?.firstOrNull()?.let { details.optJSONArray(it)?.optString(0) }
        return listOfNotNull(message, first).joinToString(": ").ifEmpty { "Bitwarden error $status" }
    }

    /** Bitwarden answers in PascalCase or camelCase depending on endpoint and version. */
    private fun JSONObject.string(vararg names: String): String? =
        names.firstNotNullOfOrNull { name -> if (has(name) && !isNull(name)) getString(name) else null }

    private fun JSONObject.int(vararg names: String): Int? =
        names.firstNotNullOfOrNull { name -> if (has(name) && !isNull(name)) getInt(name) else null }

    private fun JSONObject.kdf(): Kdf? {
        val type = int("kdf", "Kdf") ?: return null
        return Kdf(
            type,
            int("kdfIterations", "KdfIterations") ?: return null,
            int("kdfMemory", "KdfMemory"),
            int("kdfParallelism", "KdfParallelism"),
        )
    }

    private fun formBody(fields: List<Pair<String, String>>) =
        fields.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, "UTF-8")}" }

    private fun post(url: String, body: String, contentType: String): String {
        val (status, text) = request("POST", url, body, contentType)
        if (status !in 200..299) throw BitwardenException(apiError(text, status), status)
        return text
    }

    private fun request(
        method: String,
        url: String,
        body: String?,
        contentType: String?,
        headers: Map<String, String> = emptyMap(),
    ): Pair<Int, String> {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Device-Type", DEVICE_TYPE_ANDROID.toString())
            headers.forEach(::setRequestProperty)
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", contentType)
                outputStream.use { it.write(body.toByteArray()) }
            }
        }
        try {
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            return status to (stream?.bufferedReader()?.use { it.readText() }.orEmpty())
        } finally {
            connection.disconnect()
        }
    }
}
