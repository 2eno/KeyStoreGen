package io.github.keystoregen.github

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

class GitHubException(message: String, val status: Int = 0) : IOException(message)

data class Repo(val fullName: String, val private: Boolean, val admin: Boolean, val pushedAt: String?)

data class DeviceCode(
    val deviceCode: String,
    val userCode: String,
    val verificationUri: String,
    val expiresInSeconds: Int,
    val intervalSeconds: Int,
)

sealed interface TokenPoll {
    data class Token(val accessToken: String) : TokenPoll
    data object Pending : TokenPoll
    data object SlowDown : TokenPoll
    data class Failed(val reason: String) : TokenPoll
}

/** The few GitHub REST calls the app needs, on plain HttpURLConnection. All calls block. */
object GitHubApi {
    private const val API = "https://api.github.com"

    /** Classic OAuth scopes have nothing narrower that can write Actions secrets. */
    const val SCOPE = "repo"

    // OAuth device flow (https://docs.github.com/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#device-flow)

    fun requestDeviceCode(clientId: String): DeviceCode {
        val json = form("https://github.com/login/device/code", "client_id" to clientId, "scope" to SCOPE)
        if (!json.has("device_code")) throw GitHubException(oauthError(json))
        return DeviceCode(
            deviceCode = json.getString("device_code"),
            userCode = json.getString("user_code"),
            verificationUri = json.getString("verification_uri"),
            expiresInSeconds = json.getInt("expires_in"),
            intervalSeconds = json.optInt("interval", 5),
        )
    }

    fun pollToken(clientId: String, deviceCode: String): TokenPoll {
        val json = form(
            "https://github.com/login/oauth/access_token",
            "client_id" to clientId,
            "device_code" to deviceCode,
            "grant_type" to "urn:ietf:params:oauth:grant-type:device_code",
        )
        json.optString("access_token").takeIf { it.isNotEmpty() }?.let { return TokenPoll.Token(it) }
        return when (val error = json.optString("error")) {
            "authorization_pending" -> TokenPoll.Pending
            "slow_down" -> TokenPoll.SlowDown
            "expired_token" -> TokenPoll.Failed("The code expired. Start again.")
            "access_denied" -> TokenPoll.Failed("Sign-in was cancelled.")
            else -> TokenPoll.Failed(oauthError(json))
        }
    }

    private fun oauthError(json: JSONObject): String = when (val error = json.optString("error")) {
        "device_flow_disabled" -> "Device flow is off for this OAuth app. Enable it in the app's settings on GitHub."
        "incorrect_client_credentials" -> "GitHub doesn't know this app's client ID."
        else -> json.optString("error_description").ifEmpty { json.optString("message") }.ifEmpty { error }
            .ifEmpty { "Sign-in failed" }
    }

    // REST API

    fun user(token: String): String = JSONObject(request("GET", "/user", token)!!).getString("login")

    /** Repositories the user can push to, most recently pushed first. */
    fun repos(token: String, maxPages: Int = 10): List<Repo> {
        val repos = mutableListOf<Repo>()
        for (page in 1..maxPages) {
            val array = JSONArray(request("GET", "/user/repos?per_page=100&sort=pushed&page=$page", token)!!)
            for (i in 0 until array.length()) {
                val repo = array.getJSONObject(i)
                val permissions = repo.optJSONObject("permissions")
                if (permissions?.optBoolean("push") != true) continue
                repos += Repo(
                    fullName = repo.getString("full_name"),
                    private = repo.optBoolean("private"),
                    admin = permissions.optBoolean("admin"),
                    pushedAt = repo.optString("pushed_at").ifEmpty { null },
                )
            }
            if (array.length() < 100) break
        }
        return repos
    }

    /** Names of the repository's Actions secrets; values can never be read back. */
    fun secretNames(token: String, repo: String): Set<String> {
        val names = mutableSetOf<String>()
        var page = 1
        while (true) {
            val json = JSONObject(request("GET", "/repos/$repo/actions/secrets?per_page=100&page=$page", token)!!)
            val secrets = json.getJSONArray("secrets")
            for (i in 0 until secrets.length()) names += secrets.getJSONObject(i).getString("name")
            if (secrets.length() < 100) return names
            page++
        }
    }

    /** Creates or replaces Actions secrets, each sealed to the repository's public key. */
    fun putSecrets(token: String, repo: String, secrets: List<Pair<String, String>>, onEach: (String) -> Unit = {}) {
        val key = JSONObject(request("GET", "/repos/$repo/actions/secrets/public-key", token)!!)
        val keyId = key.getString("key_id")
        val publicKey = Base64.getDecoder().decode(key.getString("key"))
        for ((name, value) in secrets) {
            val sealed = SealedBox.seal(value.toByteArray(), publicKey)
            val body = JSONObject()
                .put("encrypted_value", Base64.getEncoder().encodeToString(sealed))
                .put("key_id", keyId)
            request("PUT", "/repos/$repo/actions/secrets/$name", token, body.toString())
            onEach(name)
        }
    }

    private fun request(method: String, path: String, token: String, body: String? = null): String? {
        val connection = (URL(API + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 30_000
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("Authorization", "Bearer $token")
            setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                outputStream.use { it.write(body.toByteArray()) }
            }
        }
        try {
            val status = connection.responseCode
            if (status in 200..299) {
                return if (status == 204) null else connection.inputStream.bufferedReader().use { it.readText() }
            }
            val message = connection.errorStream?.bufferedReader()?.use { it.readText() }
                ?.let { runCatching { JSONObject(it).optString("message") }.getOrNull() }
                .orEmpty()
            throw GitHubException(describe(status, message), status)
        } finally {
            connection.disconnect()
        }
    }

    private fun describe(status: Int, message: String) = when (status) {
        401 -> "GitHub rejected the sign-in. Sign in again."
        403 -> "No permission${if (message.isNotEmpty()) ": $message" else ""}. Writing secrets needs admin access to the repository, or a token with “Secrets: read and write”."
        404 -> "Not found. The repository may not exist, or the token can't see it."
        else -> "GitHub error $status${if (message.isNotEmpty()) ": $message" else ""}"
    }

    private fun form(url: String, vararg fields: Pair<String, String>): JSONObject {
        val body = fields.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, "UTF-8")}" }
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15_000
            readTimeout = 30_000
            doOutput = true
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            outputStream.use { it.write(body.toByteArray()) }
        }
        try {
            val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
            return runCatching { JSONObject(text) }.getOrElse {
                throw GitHubException("GitHub error ${connection.responseCode}", connection.responseCode)
            }
        } finally {
            connection.disconnect()
        }
    }
}
