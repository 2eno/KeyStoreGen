package io.github.keystoregen.github

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.keystoregen.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface Upload {
    data object Idle : Upload
    data object Checking : Upload
    /** Some of the secrets already exist; replacing them needs a yes from the user. */
    data class ConfirmOverwrite(val repo: String, val existing: List<String>) : Upload
    data class Uploading(val repo: String, val done: Set<String>) : Upload
    data class Done(val repo: String, val names: List<String>) : Upload
    data class Failed(val message: String) : Upload
}

class GitHubViewModel(app: Application) : AndroidViewModel(app) {
    private val store = TokenStore(app)

    /** Device flow needs the client ID of an OAuth app; without one, only tokens work. */
    val clientId: String = BuildConfig.GITHUB_CLIENT_ID
    val deviceFlowAvailable get() = clientId.isNotBlank()

    var token by mutableStateOf<String?>(null)
        private set
    var login by mutableStateOf<String?>(null)
        private set

    var deviceCode by mutableStateOf<DeviceCode?>(null)
        private set
    var signingIn by mutableStateOf(false)
        private set
    var signInError by mutableStateOf<String?>(null)
        private set

    var repos by mutableStateOf<List<Repo>>(emptyList())
        private set
    var loadingRepos by mutableStateOf(false)
        private set
    var reposError by mutableStateOf<String?>(null)
        private set

    var upload by mutableStateOf<Upload>(Upload.Idle)
        private set

    private var signInJob: Job? = null

    init {
        store.load()?.let { saved ->
            token = saved
            viewModelScope.launch {
                runCatching { io { GitHubApi.user(saved) } }
                    .onSuccess { login = it; loadRepos() }
                    .onFailure { e ->
                        // A revoked token: forget it. Offline: keep it and try again later.
                        if ((e as? GitHubException)?.status == 401) signOut()
                    }
            }
        }
    }

    fun startDeviceFlow() {
        signInJob?.cancel()
        signInError = null
        signingIn = true
        signInJob = viewModelScope.launch {
            try {
                val code = io { GitHubApi.requestDeviceCode(clientId) }
                deviceCode = code
                var interval = code.intervalSeconds
                val deadline = System.currentTimeMillis() + code.expiresInSeconds * 1000L
                while (System.currentTimeMillis() < deadline) {
                    delay(interval * 1000L)
                    when (val poll = io { GitHubApi.pollToken(clientId, code.deviceCode) }) {
                        is TokenPoll.Token -> return@launch finishSignIn(poll.accessToken)
                        TokenPoll.Pending -> Unit
                        TokenPoll.SlowDown -> interval += 5
                        is TokenPoll.Failed -> throw GitHubException(poll.reason)
                    }
                }
                throw GitHubException("The code expired. Start again.")
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                signInError = e.message ?: e.toString()
            } finally {
                deviceCode = null
                signingIn = false
            }
        }
    }

    fun signInWithToken(value: String) {
        signInJob?.cancel()
        signInError = null
        signingIn = true
        signInJob = viewModelScope.launch {
            try {
                finishSignIn(value.trim())
            } catch (e: Exception) {
                signInError = e.message ?: e.toString()
            } finally {
                signingIn = false
            }
        }
    }

    fun cancelSignIn() {
        signInJob?.cancel()
        deviceCode = null
        signingIn = false
        signInError = null
    }

    private suspend fun finishSignIn(newToken: String) {
        val name = io { GitHubApi.user(newToken) }
        store.save(newToken)
        token = newToken
        login = name
        loadRepos()
    }

    fun signOut() {
        store.clear()
        token = null
        login = null
        repos = emptyList()
        upload = Upload.Idle
    }

    fun loadRepos() {
        val token = token ?: return
        loadingRepos = true
        reposError = null
        viewModelScope.launch {
            runCatching { io { GitHubApi.repos(token) } }
                .onSuccess { repos = it }
                .onFailure { reposError = it.message }
            loadingRepos = false
        }
    }

    /** Checks for secrets of the same names first, unless [overwrite] says that's settled. */
    fun uploadSecrets(repo: String, secrets: List<Pair<String, String>>, overwrite: Boolean = false) {
        val token = token ?: return
        val names = secrets.map { it.first }
        viewModelScope.launch {
            try {
                if (!overwrite) {
                    upload = Upload.Checking
                    val existing = io { GitHubApi.secretNames(token, repo) }.let { have -> names.filter { it in have } }
                    if (existing.isNotEmpty()) {
                        upload = Upload.ConfirmOverwrite(repo, existing)
                        return@launch
                    }
                }
                upload = Upload.Uploading(repo, emptySet())
                io {
                    GitHubApi.putSecrets(token, repo, secrets) { name ->
                        val current = upload
                        if (current is Upload.Uploading) upload = current.copy(done = current.done + name)
                    }
                }
                upload = Upload.Done(repo, names)
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                upload = Upload.Failed(e.message ?: e.toString())
            }
        }
    }

    fun dismissUpload() {
        upload = Upload.Idle
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}
