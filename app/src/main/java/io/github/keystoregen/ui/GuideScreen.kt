package io.github.keystoregen.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.SwapHoriz
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.keystoregen.MainViewModel
import io.github.keystoregen.Snippets

/** The whole setup, from key to signed CI release, using the values from the Generate tab. */
@Composable
fun GuideScreen(vm: MainViewModel, actions: Actions, modifier: Modifier = Modifier) {
    val alias = vm.alias.trim().ifEmpty { "release" }
    val names = vm.secretNames
    Column(
        modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Note(
            "Only what gets installed needs a key: the APK or app bundle. Other build outputs, such as patch bundles or plugins that are never installed as apps, aren't checked for a signature.",
            Icons.Outlined.Info,
        )

        SectionCard("Create a keystore once", badge = "1") {
            Body("Use the Generate tab, or keytool on your computer. Back the keystore up: if you lose it you can never publish an update that installs over the old app.")
            CodeBlock(Snippets.keytool(alias, vm.years ?: 100, vm.keyType)) {
                actions.copy("keytool command", Snippets.keytool(alias, vm.years ?: 100, vm.keyType), false)
            }
            Body("keytool asks for a keystore password and a key password, plus name details, which can be anything. Pressing Enter at the key-password prompt reuses the keystore password.")
        }

        SectionCard("Encode it as base64", badge = "2") {
            Body("CI secrets are text, so the keystore goes in as base64. The app's ${names.keystore} value already is; for a keytool keystore:")
            CodeBlock(Snippets.base64Commands(alias)) { actions.copy("base64 commands", Snippets.base64Commands(alias), false) }
        }

        SectionCard("Add four repository secrets", badge = "3") {
            Body("Quickest: after generating, sign in with GitHub on the Generate tab, pick the repository and add all four in one tap. By hand: github.com/OWNER/REPO → Settings → Secrets and variables → Actions → New repository secret:")
            SecretTable(
                listOf(
                    names.keystore to "the base64 keystore (keystore.txt)",
                    names.password to "the keystore password",
                    names.alias to "$alias (the -alias above)",
                    names.aliasPassword to "the key password",
                ),
            )
        }

        SectionCard("Sign in CI", badge = "4") {
            Body("Decode the keystore in the workflow and hand the rest to Gradle as environment variables:")
            CodeBlock(Snippets.workflowStep(names)) { actions.copy("Workflow steps", Snippets.workflowStep(names), false) }
            Body("Gradle reads them from signing.properties or the environment:")
            CodeBlock(Snippets.gradle(names)) { actions.copy("Gradle config", Snippets.gradle(names), false) }
            Body("A good habit: let stable releases fail when the secrets are missing, so nothing ships signed with a throwaway debug key.")
        }

        SectionCard("Optional: signed builds on your computer", badge = "5") {
            Body("Put the .jks in the repository root and create signing.properties next to it. Add both to .gitignore.")
            CodeBlock(
                """
                |${names.password}=...
                |${names.alias}=$alias
                |${names.aliasPassword}=...
                |KEYSTORE_FILE=../$alias.jks
                """.trimMargin(),
            )
            Body("The ../ is needed because the path is relative to the app/ folder.")
        }

        SectionCard("Changing keys", icon = Icons.Outlined.SwapHoriz) {
            Body("Android requires the same key for updates. The first build signed with a new key can't install over one signed with another key, debug keys included, so users have to uninstall once, which also deletes the app's data. Add the secrets before anyone relies on your builds, and re-run the latest release once they exist, to keep that to one uninstall.")
        }
        Spacer(Modifier.height(8.dp))
    }
}

@Composable
private fun SecretTable(rows: List<Pair<String, String>>) {
    Column {
        rows.forEachIndexed { i, (name, value) ->
            if (i > 0) HorizontalDivider()
            Row(Modifier.padding(vertical = 10.dp)) {
                Text(
                    name,
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1.1f),
                )
                Spacer(Modifier.width(12.dp))
                Text(value, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
            }
        }
    }
}
