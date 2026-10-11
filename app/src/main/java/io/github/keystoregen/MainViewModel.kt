package io.github.keystoregen

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Holds the form and the generated key. The key lives only in memory: it survives
 * rotation, but is gone once the app process ends, unless the user saved it.
 */
class MainViewModel : ViewModel() {
    // Key
    var alias by mutableStateOf("release")
    var validityYears by mutableStateOf("100")
    var keyType by mutableStateOf(KeyType.RSA_4096)

    // Certificate subject
    var commonName by mutableStateOf("")
    var organizationalUnit by mutableStateOf("")
    var organization by mutableStateOf("")
    var locality by mutableStateOf("")
    var state by mutableStateOf("")
    var country by mutableStateOf("")

    // Password
    var customPassword by mutableStateOf(false)
    var password by mutableStateOf("")

    // CI
    var secretPrefix by mutableStateOf("")
    var repository by mutableStateOf("")

    // Bitwarden export
    var filePassword by mutableStateOf("")
    var filePasswordConfirm by mutableStateOf("")

    var keystore by mutableStateOf<GeneratedKeystore?>(null)
        private set
    var generating by mutableStateOf(false)
        private set
    var exporting by mutableStateOf(false)
        private set

    val secretNames get() = SecretNames(secretPrefix.trim())
    val years get() = validityYears.toIntOrNull()

    /** The owner/name part of whatever the user pasted: a URL, a git remote or owner/name. */
    val repositoryPath: String?
        get() = Regex("""(?:github\.com[/:])?([\w.-]+/[\w.-]+?)(?:\.git)?/?$""")
            .find(repository.trim())?.groupValues?.get(1)

    val aliasError get() = when {
        alias.isBlank() -> "Required"
        alias.any { it.isWhitespace() } -> "No spaces"
        else -> null
    }
    val yearsError get() = if (years?.let { it in 1..1000 } == true) null else "1 to 1000"
    val countryError get() = if (country.isEmpty() || Regex("[A-Za-z]{2}").matches(country)) null else "Two letters, e.g. DE"
    val passwordError get() = if (!customPassword || password.length >= 6) null else "At least 6 characters"
    val prefixError get() = if (SecretNames.isValidPrefix(secretPrefix.trim())) null else "Letters, digits and _ only"

    val canGenerate get() = !generating && listOf(aliasError, yearsError, countryError, passwordError).all { it == null }

    val filePasswordError get() = when {
        filePassword.isNotEmpty() && filePassword.length < BitwardenExport.MIN_PASSWORD_LENGTH ->
            "At least ${BitwardenExport.MIN_PASSWORD_LENGTH} characters"
        else -> null
    }
    val filePasswordConfirmError get() =
        if (filePasswordConfirm.isNotEmpty() && filePasswordConfirm != filePassword) "Doesn't match" else null
    val canExport get() = !exporting && keystore != null &&
        filePassword.length >= BitwardenExport.MIN_PASSWORD_LENGTH && filePassword == filePasswordConfirm

    fun generate(onError: (Throwable) -> Unit) {
        val years = years ?: return
        val alias = alias.trim()
        val password = if (customPassword) password else KeystoreGenerator.randomPassword()
        val subject = Subject(
            commonName = commonName.trim().ifEmpty { alias },
            organizationalUnit = organizationalUnit.trim(),
            organization = organization.trim(),
            locality = locality.trim(),
            state = state.trim(),
            country = country.trim(),
        )
        val type = keyType
        generating = true
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.Default) {
                    KeystoreGenerator.generate(alias, password, subject, years, type)
                }
            }.onSuccess { keystore = it }.onFailure(onError)
            generating = false
        }
    }

    fun bitwardenItemName(keystore: GeneratedKeystore): String {
        val app = repositoryPath?.substringAfter('/') ?: commonName.trim().ifEmpty { null }
        return if (app != null) "$app signing key (${keystore.alias})" else "Signing key (${keystore.alias})"
    }

    fun exportBitwarden(onDone: (Result<ByteArray>) -> Unit) {
        val keystore = keystore ?: return
        val password = filePassword
        val itemName = bitwardenItemName(keystore)
        val names = secretNames
        exporting = true
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.Default) {
                    BitwardenExport.encryptedJson(BitwardenExport.plainJson(keystore, itemName, names), password)
                        .toByteArray()
                }
            }
            exporting = false
            onDone(result)
        }
    }
}
