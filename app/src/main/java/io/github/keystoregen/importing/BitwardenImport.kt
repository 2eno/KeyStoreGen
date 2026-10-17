package io.github.keystoregen.importing

import io.github.keystoregen.BitwardenExport
import java.util.Base64
import org.json.JSONObject

/** A Bitwarden item whose notes hold a base64 keystore, with whatever secrets its fields carry. */
data class BitwardenKeystore(
    val itemName: String,
    val bytes: ByteArray,
    val storePassword: String?,
    val alias: String?,
    val keyPassword: String?,
    /** The secret name prefix the fields use, e.g. "WEAR_" for WEAR_KEYSTORE_ALIAS. */
    val prefix: String,
)

class PasswordNeededException : IllegalArgumentException("This export is password protected")

/**
 * Reads Bitwarden JSON exports: unencrypted, or password protected (PBKDF2 or Argon2id).
 * Account-encrypted exports can only be opened by Bitwarden itself.
 */
object BitwardenImport {
    fun isPasswordProtected(json: String) = runCatching { JSONObject(json).optBoolean("passwordProtected") }.getOrDefault(false)

    fun read(json: String, filePassword: String? = null): List<BitwardenKeystore> {
        val root = runCatching { JSONObject(json) }.getOrElse { throw IllegalArgumentException("This isn't a Bitwarden JSON export") }
        val vault = when {
            !root.optBoolean("encrypted") -> root
            root.optBoolean("passwordProtected") -> JSONObject(decrypt(root, filePassword ?: throw PasswordNeededException()))
            else -> throw IllegalArgumentException(
                "This export is encrypted with your Bitwarden account key, which only Bitwarden can read. " +
                    "Export again as “.json (Password protected)” or plain “.json”.",
            )
        }
        val items = vault.optJSONArray("items") ?: throw IllegalArgumentException("This isn't a Bitwarden JSON export")
        return (0 until items.length()).mapNotNull { candidate(items.getJSONObject(it)) }
            .also { require(it.isNotEmpty()) { "No item in this export has a keystore in its notes" } }
    }

    private fun decrypt(root: JSONObject, password: String): String {
        val salt = root.getString("salt")
        val iterations = root.getInt("kdfIterations")
        val key = when (val kdf = root.optInt("kdfType", 0)) {
            0 -> BitwardenExport.deriveKey(password, salt, iterations)
            1 -> BitwardenExport.deriveKeyArgon2(password, salt, iterations, root.getInt("kdfMemory"), root.getInt("kdfParallelism"))
            else -> throw IllegalArgumentException("Unknown Bitwarden KDF $kdf")
        }
        try {
            BitwardenExport.decrypt(root.getString("encKeyValidation_DO_NOT_EDIT"), key)
        } catch (e: Exception) {
            throw WrongPasswordException("Wrong file password")
        }
        return BitwardenExport.decrypt(root.getString("data"), key)
    }

    private fun candidate(item: JSONObject): BitwardenKeystore? {
        val notes = item.optString("notes").filterNot(Char::isWhitespace)
        if (notes.length < 64) return null
        val bytes = runCatching { Base64.getDecoder().decode(notes) }.getOrNull() ?: return null
        if (runCatching { KeystoreLoader.format(bytes) }.isFailure) return null

        val fields = item.optJSONArray("fields")?.let { array ->
            (0 until array.length()).associate { i ->
                array.getJSONObject(i).let { it.optString("name").trim() to it.optString("value") }
            }
        }.orEmpty()
        val aliasField = fields.keys.firstOrNull { it.endsWith("KEYSTORE_ALIAS") }
        val prefix = aliasField?.removeSuffix("KEYSTORE_ALIAS")
            ?: fields.keys.firstOrNull { it.endsWith("KEYSTORE_PASSWORD") && !it.endsWith("ALIAS_PASSWORD") }
                ?.removeSuffix("KEYSTORE_PASSWORD")
            ?: ""
        val loginPassword = item.optJSONObject("login")?.optString("password")?.ifEmpty { null }
        return BitwardenKeystore(
            itemName = item.optString("name").ifEmpty { "Unnamed item" },
            bytes = bytes,
            storePassword = fields["${prefix}KEYSTORE_PASSWORD"]?.ifEmpty { null } ?: loginPassword,
            alias = fields["${prefix}KEYSTORE_ALIAS"]?.ifEmpty { null },
            keyPassword = fields["${prefix}KEYSTORE_ALIAS_PASSWORD"]?.ifEmpty { null },
            prefix = prefix,
        )
    }
}
