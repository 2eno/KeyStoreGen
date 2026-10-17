import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Release signing: signing.properties in the repo root (local builds) or
// environment variables of the same names (CI). KEYSTORE_FILE is resolved
// relative to this app/ folder. Without either, release builds fall back to
// the throwaway debug key.
val signingProps = Properties().apply {
    val file = rootProject.file("signing.properties")
    if (file.exists()) file.inputStream().use(::load)
}

fun signingValue(name: String): String? =
    (signingProps.getProperty(name) ?: System.getenv(name))?.takeIf { it.isNotBlank() }

val releaseKeystore = signingValue("KEYSTORE_FILE")?.let(::file)?.takeIf { it.exists() }

android {
    namespace = "io.github.keystoregen"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.keystoregen"
        minSdk = 29
        targetSdk = 36
        versionCode = (findProperty("versionCode") as String?)?.toInt() ?: 1
        versionName = (findProperty("versionName") as String?) ?: "1.0.0"

        // Client ID of a GitHub OAuth app with device flow enabled (see README). It is
        // public by design; without it, sign-in falls back to pasting a token.
        val githubClientId = (findProperty("githubClientId") as String?)?.takeIf { it.isNotBlank() }
            ?: System.getenv("GH_OAUTH_CLIENT_ID") ?: ""
        buildConfigField("String", "GITHUB_CLIENT_ID", "\"$githubClientId\"")
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = signingValue("KEYSTORE_PASSWORD")
                keyAlias = signingValue("KEYSTORE_ALIAS")
                keyPassword = signingValue("KEYSTORE_ALIAS_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)

    // X25519, XSalsa20-Poly1305 and BLAKE2b for GitHub's sealed-box secret encryption.
    implementation(libs.bouncycastle)

    testImplementation(libs.junit)
    // The real org.json, since android.jar only has stubs on the JVM.
    testImplementation(libs.org.json)
}
