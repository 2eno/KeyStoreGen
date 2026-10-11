package io.github.keystoregen

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BitwardenExportTest {
    private fun field(json: String, name: String) =
        Regex(""""$name":"([^"]*)"""").find(json)!!.groupValues[1]

    @Test
    fun exportDecryptsWithTheFilePassword() {
        val keystore = KeystoreGenerator.generate("release", "secret-password", Subject("App"), 1, KeyType.EC_P256)
        val plain = BitwardenExport.plainJson(keystore, "App signing key (release)", SecretNames("APP_"))
        val encrypted = BitwardenExport.encryptedJson(plain, "a long file password")

        val key = BitwardenExport.deriveKey("a long file password", field(encrypted, "salt"), BitwardenExport.KDF_ITERATIONS)
        // Throws on a wrong key, which is how Bitwarden checks the password.
        BitwardenExport.decrypt(field(encrypted, "encKeyValidation_DO_NOT_EDIT"), key)
        val decrypted = BitwardenExport.decrypt(field(encrypted, "data"), key)

        assertEquals(plain, decrypted)
        assertEquals(keystore.base64, field(decrypted, "notes"))
        assertTrue(decrypted.contains(""""name":"APP_KEYSTORE_ALIAS","value":"release""""))
    }

    @Test
    fun jsonStringsAreEscaped() {
        val keystore = KeystoreGenerator.generate("a", "pass\"word\\", Subject("a"), 1, KeyType.EC_P256)
        val plain = BitwardenExport.plainJson(keystore, "quote \" and\nnewline", SecretNames())
        assertTrue(plain.contains("""quote \" and\u000anewline"""))
        assertTrue(plain.contains("""pass\"word\\"""))
    }
}
