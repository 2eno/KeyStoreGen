package io.github.keystoregen.importing

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.keystoregen.SigningKeystore
import java.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class ImportSource(val label: String) { FILE("Keystore file"), BITWARDEN("Bitwarden"), PASTE("Paste") }

/**
 * Brings an existing keystore into the app: from a .jks/.p12 file, from a Bitwarden JSON
 * export (as this app writes them), or pasted as base64, e.g. copied from a Bitwarden note.
 * Unlocking goes in two steps: the keystore password lists the keys, the key password opens one.
 */
class ImportViewModel : ViewModel() {
    var source by mutableStateOf(ImportSource.FILE)
        private set

    /** Name of the picked file, for display. */
    var fileName by mutableStateOf<String?>(null)
        private set

    // Bitwarden
    private var bitwardenJson: String? = null
    var needsFilePassword by mutableStateOf(false)
        private set
    var filePassword by mutableStateOf("")
    var items by mutableStateOf<List<BitwardenKeystore>>(emptyList())
        private set
    var selectedItem by mutableStateOf<BitwardenKeystore?>(null)
        private set

    // Paste
    var pasted by mutableStateOf("")

    // The keystore being opened
    private var bytes: ByteArray? = null
    var storePassword by mutableStateOf("")
    var entries by mutableStateOf<List<KeyEntry>>(emptyList())
        private set
    var alias by mutableStateOf<String?>(null)
    var separateKeyPassword by mutableStateOf(false)
    var keyPassword by mutableStateOf("")
    var detectedPrefix by mutableStateOf<String?>(null)
        private set

    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
        private set

    val hasKeystore get() = bytes != null
    val format get() = bytes?.let { runCatching { KeystoreLoader.format(it).label }.getOrNull() }

    fun selectSource(value: ImportSource) {
        if (value == source) return
        reset()
        source = value
    }

    fun reset() {
        fileName = null
        bitwardenJson = null
        needsFilePassword = false
        filePassword = ""
        items = emptyList()
        selectedItem = null
        pasted = ""
        clearKeystore()
        error = null
    }

    private fun clearKeystore() {
        bytes = null
        storePassword = ""
        entries = emptyList()
        alias = null
        separateKeyPassword = false
        keyPassword = ""
        detectedPrefix = null
    }

    /** A picked file: a keystore, or a Bitwarden export depending on [source]. */
    fun fileLoaded(name: String, content: ByteArray) {
        reset()
        fileName = name
        if (source == ImportSource.BITWARDEN) {
            val json = content.toString(Charsets.UTF_8)
            bitwardenJson = json
            if (BitwardenImport.isPasswordProtected(json)) needsFilePassword = true else readBitwarden()
        } else {
            useBytes(content)
        }
    }

    fun fileFailed(message: String) {
        error = message
    }

    fun readBitwarden() {
        val json = bitwardenJson ?: return
        val password = filePassword.takeIf { needsFilePassword }
        work {
            // Argon2id and 600,000 rounds of PBKDF2 both take a moment.
            val found = withContext(Dispatchers.Default) { BitwardenImport.read(json, password) }
            needsFilePassword = false
            items = found
            if (found.size == 1) selectItem(found.single())
        }
    }

    fun selectItem(item: BitwardenKeystore) {
        clearKeystore()
        selectedItem = item
        bytes = item.bytes
        detectedPrefix = item.prefix
        storePassword = item.storePassword.orEmpty()
        keyPassword = item.keyPassword ?: storePassword
        separateKeyPassword = item.keyPassword != null && item.keyPassword != item.storePassword
        // The export carries the passwords: open it right away if they fit.
        if (item.storePassword != null) unlock(preferredAlias = item.alias)
    }

    fun usePasted() {
        val text = pasted.filterNot(Char::isWhitespace)
        val decoded = runCatching { Base64.getDecoder().decode(text) }.getOrNull()
        if (decoded == null || decoded.isEmpty()) {
            error = "That isn't base64"
            return
        }
        clearKeystore()
        useBytes(decoded)
    }

    private fun useBytes(content: ByteArray) {
        error = null
        try {
            KeystoreLoader.format(content)
            bytes = content
        } catch (e: IllegalArgumentException) {
            error = e.message
        }
    }

    /** Opens the keystore with [storePassword] and lists its keys. */
    fun unlock(preferredAlias: String? = null) {
        val content = bytes ?: return
        val password = storePassword
        work {
            val found = withContext(Dispatchers.Default) { KeystoreLoader.entries(content, password) }
            entries = found
            alias = found.firstOrNull { it.alias == preferredAlias }?.alias ?: found.first().alias
        }
    }

    /** Checks the key password and hands the keystore over. */
    fun finish(onDone: (SigningKeystore, prefix: String?) -> Unit) {
        val content = bytes ?: return
        val alias = alias ?: return
        val store = storePassword
        val key = if (separateKeyPassword) keyPassword else store
        work {
            val keystore = withContext(Dispatchers.Default) { KeystoreLoader.open(content, store, alias, key) }
            onDone(keystore, detectedPrefix)
        }
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
                error = when (e) {
                    is WrongPasswordException, is IllegalArgumentException -> e.message
                    else -> e.message ?: e.toString()
                }
                if (e is WrongPasswordException && e.message == "Wrong key password") separateKeyPassword = true
            } finally {
                busy = false
            }
        }
    }
}
