package io.github.keystoregen.importing

import io.github.keystoregen.BitwardenExport
import io.github.keystoregen.KeyType
import io.github.keystoregen.KeystoreGenerator
import io.github.keystoregen.SecretNames
import io.github.keystoregen.Subject
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BitwardenImportTest {
    private val keystore = KeystoreGenerator.generate("release", "store-pass", Subject("App"), 25, KeyType.EC_P256)

    @Test
    fun readsThisAppsPasswordProtectedExport() {
        val plain = BitwardenExport.plainJson(keystore, "App signing key", SecretNames("WEAR_"))
        val export = BitwardenExport.encryptedJson(plain, "a long file password")
        assertEquals(true, BitwardenImport.isPasswordProtected(export))

        val item = BitwardenImport.read(export, "a long file password").single()
        assertEquals("App signing key", item.itemName)
        assertArrayEquals(keystore.bytes, item.bytes)
        assertEquals("store-pass", item.storePassword)
        assertEquals("release", item.alias)
        assertEquals("store-pass", item.keyPassword)
        assertEquals("WEAR_", item.prefix)
    }

    @Test(expected = WrongPasswordException::class)
    fun wrongFilePassword() {
        val export = BitwardenExport.encryptedJson(BitwardenExport.plainJson(keystore, "x", SecretNames()), "a long file password")
        BitwardenImport.read(export, "not the password")
    }

    @Test(expected = PasswordNeededException::class)
    fun asksForTheFilePassword() {
        val export = BitwardenExport.encryptedJson(BitwardenExport.plainJson(keystore, "x", SecretNames()), "a long file password")
        BitwardenImport.read(export)
    }

    /** A hand-made item: keystore in the notes with line breaks, passwords only partly in fields. */
    @Test
    fun readsPlainExportsAndSkipsOtherItems() {
        val notes = Base64.getMimeEncoder().encodeToString(keystore.bytes).replace("\r\n", "\\n")
        val json = """{"encrypted":false,"items":[
            {"type":1,"name":"Some login","notes":"not a keystore","login":{"password":"x"}},
            {"type":1,"name":"Keystore login","notes":"$notes","login":{"password":"store-pass"}}
        ]}"""
        val item = BitwardenImport.read(json).single()
        assertEquals("Keystore login", item.itemName)
        assertEquals("store-pass", item.storePassword)
        assertNull(item.alias)
        assertEquals("", item.prefix)
    }

    @Test(expected = IllegalArgumentException::class)
    fun accountEncryptedExportsAreExplained() {
        BitwardenImport.read("""{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.x","items":[]}""")
    }

    /** Reference values from argon2-cffi plus HMAC-SHA256, following Bitwarden's key derivation. */
    @Test
    fun argon2MatchesBitwarden() {
        val key = BitwardenExport.deriveKeyArgon2("correct horse battery", "c2FsdHNhbHRzYWx0c2FsdA==", 3, 16, 2)
        assertEquals("roeN+TXeQw8fUP48LPH+3lLEOYTkdVkJjPmyyvEttmQ=", Base64.getEncoder().encodeToString(key.enc))
        assertEquals("YCgw1ZEVkkSc5zjBXpc9kIPmvT9vRsdQo/eYVLfbe64=", Base64.getEncoder().encodeToString(key.mac))
    }

    @Test
    fun readsArgon2Exports() {
        val salt = "c2FsdHNhbHRzYWx0c2FsdA=="
        val key = BitwardenExport.deriveKeyArgon2("pw", salt, 3, 16, 2)
        val plain = BitwardenExport.plainJson(keystore, "Argon item", SecretNames())
        val export = """{"encrypted":true,"passwordProtected":true,"salt":"$salt","kdfType":1,"kdfIterations":3,""" +
            """"kdfMemory":16,"kdfParallelism":2,"encKeyValidation_DO_NOT_EDIT":"${BitwardenExport.encrypt("check", key)}",""" +
            """"data":"${BitwardenExport.encrypt(plain, key)}"}"""
        assertEquals("Argon item", BitwardenImport.read(export, "pw").single().itemName)
    }
}
