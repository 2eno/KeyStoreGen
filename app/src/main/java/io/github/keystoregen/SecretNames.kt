package io.github.keystoregen

/**
 * Names of the four CI secrets. The defaults match the common Android release workflow
 * (and this repo's own); a prefix helps when one repository signs several apps.
 */
data class SecretNames(val prefix: String = "") {
    val keystore get() = "${prefix}KEYSTORE"
    val password get() = "${prefix}KEYSTORE_PASSWORD"
    val alias get() = "${prefix}KEYSTORE_ALIAS"
    val aliasPassword get() = "${prefix}KEYSTORE_ALIAS_PASSWORD"

    companion object {
        /** Secret names may only hold letters, digits and underscores, and can't start with a digit. */
        fun isValidPrefix(prefix: String) = prefix.isEmpty() || Regex("[A-Za-z_][A-Za-z0-9_]*").matches(prefix)
    }
}

/** A secret the user copies into GitHub, with the value it gets. */
data class Secret(val name: String, val value: String, val sensitive: Boolean, val hint: String)

fun GeneratedKeystore.secrets(names: SecretNames) = listOf(
    Secret(names.keystore, base64, true, "The keystore file, base64-encoded"),
    Secret(names.password, password, true, "Keystore password"),
    Secret(names.alias, alias, false, "Key alias"),
    Secret(names.aliasPassword, password, true, "Key password (same as the keystore's)"),
)

object Snippets {
    /** signing.properties for local builds; the path is relative to the app/ module. */
    fun signingProperties(keystore: GeneratedKeystore, names: SecretNames) = """
        |${names.password}=${keystore.password}
        |${names.alias}=${keystore.alias}
        |${names.aliasPassword}=${keystore.password}
        |KEYSTORE_FILE=../${keystore.alias}.jks
        |""".trimMargin()

    fun keytool(alias: String, years: Int, keyType: KeyType): String {
        val algorithm = when (keyType) {
            KeyType.EC_P256 -> "-keyalg EC -groupname secp256r1"
            else -> "-keyalg RSA -keysize ${keyType.name.removePrefix("RSA_")}"
        }
        return "keytool -genkeypair -v -keystore $alias.jks -alias $alias \\\n  $algorithm -validity ${years * 365}"
    }

    fun base64Commands(alias: String) = """
        |base64 -w0 $alias.jks > keystore.txt      # Linux
        |base64 -i $alias.jks -o keystore.txt      # macOS
        |""".trimMargin()

    fun gradle(names: SecretNames) = """
        |// app/build.gradle.kts
        |val signingProps = java.util.Properties().apply {
        |    rootProject.file("signing.properties").takeIf { it.exists() }?.inputStream()?.use(::load)
        |}
        |fun signing(name: String) = signingProps.getProperty(name) ?: System.getenv(name)
        |
        |android {
        |    signingConfigs {
        |        create("release") {
        |            storeFile = signing("KEYSTORE_FILE")?.let(::file)
        |            storePassword = signing("${names.password}")
        |            keyAlias = signing("${names.alias}")
        |            keyPassword = signing("${names.aliasPassword}")
        |        }
        |    }
        |    buildTypes {
        |        release { signingConfig = signingConfigs.getByName("release") }
        |    }
        |}
        |""".trimMargin()

    fun workflowStep(names: SecretNames) = """
        |- name: Decode keystore
        |  env:
        |    ${names.keystore}: ${'$'}{{ secrets.${names.keystore} }}
        |  run: |
        |    if [ -n "${'$'}${names.keystore}" ]; then
        |      echo "${'$'}${names.keystore}" | base64 -d > "${'$'}RUNNER_TEMP/release.jks"
        |      echo "KEYSTORE_FILE=${'$'}RUNNER_TEMP/release.jks" >> "${'$'}GITHUB_ENV"
        |    fi
        |
        |- name: Build release APK
        |  env:
        |    ${names.password}: ${'$'}{{ secrets.${names.password} }}
        |    ${names.alias}: ${'$'}{{ secrets.${names.alias} }}
        |    ${names.aliasPassword}: ${'$'}{{ secrets.${names.aliasPassword} }}
        |  run: ./gradlew assembleRelease
        |""".trimMargin()
}
