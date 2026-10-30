package io.github.keystoregen.bitwarden

import android.app.Application
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.edit
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.keystoregen.SecretNames
import io.github.keystoregen.SigningKeystore
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class Region(val label: String) { US("bitwarden.com"), EU("bitwarden.eu"), SELF_HOSTED("Self-hosted") }

sealed interface VaultSave {
    data object Idle : VaultSave
    data object Saving : VaultSave
    data class Saved(val itemName: String) : VaultSave
    data class Failed(val message: String) : VaultSave
}

/**
 * Bitwarden sign-in and saving. The unlocked session lives in memory only and is gone
 * with the app; only the server, email and this device's id are remembered.
 */
class BitwardenViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("bitwarden", 0)

    /** Stable per install, so Bitwarden doesn't treat every login as a new device. */
    private val deviceId: String = prefs.getString("device_id", null)
        ?: UUID.randomUUID().toString().also { id -> prefs.edit { putString("device_id", id) } }
    private val deviceName = "KeyStoreGen on ${Build.MODEL}"

    var region by mutableStateOf(prefs.getString("region", null)?.let { runCatching { Region.valueOf(it) }.getOrNull() } ?: Region.US)
    var selfHostedUrl by mutableStateOf(prefs.getString("server", "").orEmpty())
    var email by mutableStateOf(prefs.getString("email", "").orEmpty())
    var masterPassword by mutableStateOf("")
    var useApiKey by mutableStateOf(false)
    var clientId by mutableStateOf("")
    var clientSecret by mutableStateOf("")

    var challenge by mutableStateOf<LoginChallenge?>(null)
        private set
    var twoFactorProvider by mutableStateOf(0)
    var code by mutableStateOf("")

    var session by mutableStateOf<BitwardenSession?>(null)
        private set
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
        private set
    var info by mutableStateOf<String?>(null)
        private set

    var save by mutableStateOf<VaultSave>(VaultSave.Idle)
        private set

    val canSignIn get() = !busy && email.contains('@') && masterPassword.isNotEmpty() &&
        (!useApiKey || (clientId.isNotBlank() && clientSecret.isNotBlank())) &&
        (region != Region.SELF_HOSTED || selfHostedUrl.isNotBlank()) &&
        (challenge == null || code.isNotBlank())

    private fun server(): BitwardenServer = when (region) {
        Region.US -> BitwardenServer.US
        Region.EU -> BitwardenServer.EU
        Region.SELF_HOSTED -> BitwardenServer.selfHosted(selfHostedUrl)
    }

    fun signIn() {
        val credentials = Credentials(
            email = email,
            masterPassword = masterPassword,
            clientId = clientId.trim().takeIf { useApiKey },
            clientSecret = clientSecret.trim().takeIf { useApiKey },
            twoFactorProvider = twoFactorProvider.takeIf { challenge is LoginChallenge.TwoFactor },
            twoFactorCode = code.takeIf { challenge is LoginChallenge.TwoFactor },
            newDeviceCode = code.takeIf { challenge is LoginChallenge.NewDevice },
        )
        work {
            val server = server()
            try {
                session = io { BitwardenApi.login(server, credentials, deviceId, deviceName) }
                prefs.edit {
                    putString("region", region.name)
                    putString("server", selfHostedUrl)
                    putString("email", email.trim())
                }
                masterPassword = ""
                clientSecret = ""
                code = ""
                challenge = null
                info = null
            } catch (c: LoginChallenge) {
                code = ""
                info = when (c) {
                    LoginChallenge.NewDevice -> "Bitwarden emailed a verification code to ${email.trim()}, because the app is a new device for your account."
                    is LoginChallenge.TwoFactor -> {
                        // Prefer the authenticator app; email codes have to be requested first.
                        twoFactorProvider = if (0 in c.providers) 0 else c.providers.firstOrNull() ?: 0
                        if (c.providers.none { it == 0 || it == 1 }) {
                            throw BitwardenException("Your two-step login uses a method the app can't handle (only authenticator apps and email codes). Sign in with your personal API key instead.")
                        }
                        null
                    }
                }
                challenge = c
            }
        }
    }

    fun sendEmailCode() {
        val server = runCatching { server() }.getOrElse { error = it.message; return }
        work {
            io { BitwardenApi.sendEmailCode(server, email, masterPassword, deviceId) }
            info = "Code sent to ${(challenge as? LoginChallenge.TwoFactor)?.emailHint ?: email.trim()}"
        }
    }

    fun cancelSignIn() {
        challenge = null
        code = ""
        error = null
        info = null
    }

    fun signOut() {
        session = null
        save = VaultSave.Idle
        masterPassword = ""
    }

    fun saveKeystore(keystore: SigningKeystore, itemName: String, names: SecretNames) {
        val session = session ?: return
        save = VaultSave.Saving
        viewModelScope.launch {
            save = try {
                io { BitwardenApi.saveKeystore(session, keystore, itemName, names) }
                VaultSave.Saved(itemName)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                if ((e as? BitwardenException)?.status == 401) this@BitwardenViewModel.session = null
                VaultSave.Failed(e.message ?: e.toString())
            }
        }
    }

    fun resetSave() {
        save = VaultSave.Idle
    }

    private fun work(block: suspend () -> Unit) {
        busy = true
        error = null
        viewModelScope.launch {
            try {
                block()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                error = e.message ?: e.toString()
            } finally {
                busy = false
            }
        }
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}
