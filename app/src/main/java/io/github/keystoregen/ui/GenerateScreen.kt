package io.github.keystoregen.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.expandVertically
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Badge
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Save
import androidx.compose.material.icons.outlined.WarningAmber
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.keystoregen.KeyType
import io.github.keystoregen.MainViewModel
import io.github.keystoregen.Snippets
import io.github.keystoregen.secrets
import java.text.DateFormat

@Composable
fun GenerateScreen(vm: MainViewModel, actions: Actions, onGenerate: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier
            .fillMaxSize()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Body("Creates an Android app signing key, the same as keytool -genkeypair, and gets it into your CI secrets and password manager. Nothing leaves the phone unless you save or copy it.")

        KeyCard(vm)
        PasswordCard(vm)

        Button(
            onClick = onGenerate,
            enabled = vm.canGenerate,
            modifier = Modifier.fillMaxWidth().height(56.dp),
        ) {
            if (vm.generating) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                Spacer(Modifier.size(12.dp))
                Text("Generating… (can take a few seconds)")
            } else {
                Text(if (vm.keystore == null) "Generate keystore" else "Generate a new keystore")
            }
        }

        val keystore = vm.keystore
        AnimatedVisibility(keystore != null, enter = fadeIn() + expandVertically()) {
            if (keystore != null) {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    ResultCard(vm, actions)
                    BitwardenCard(vm, actions)
                    SecretsCard(vm, actions)
                    LocalBuildCard(vm, actions)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun KeyCard(vm: MainViewModel) {
    SectionCard("Key", icon = Icons.Outlined.Badge) {
        Field(
            vm.alias, { vm.alias = it }, "Key alias",
            supporting = "Becomes KEYSTORE_ALIAS and the file name",
            error = vm.aliasError,
        )
        Field(
            vm.validityYears, { vm.validityYears = it.filter(Char::isDigit).take(4) }, "Valid for (years)",
            supporting = "Google Play asks for 25+ years; the key can never be renewed",
            error = vm.yearsError, number = true,
        )
        Text("Algorithm", style = MaterialTheme.typography.labelLarge)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyType.entries.forEach { type ->
                FilterChip(
                    selected = vm.keyType == type,
                    onClick = { vm.keyType = type },
                    label = { Text(type.label) },
                    leadingIcon = if (vm.keyType == type) {
                        { Icon(Icons.Outlined.CheckCircle, null, Modifier.size(FilterChipDefaults.IconSize)) }
                    } else null,
                )
            }
        }
        Body(vm.keyType.detail)

        Expandable(
            "Certificate details",
            summary = "Optional. Only the name is shown anywhere, e.g. in “Signed by”",
        ) {
            Field(vm.commonName, { vm.commonName = it }, "Name (CN)", supporting = "Defaults to the alias")
            Field(vm.organization, { vm.organization = it }, "Organization (O)")
            Field(vm.organizationalUnit, { vm.organizationalUnit = it }, "Organizational unit (OU)")
            Field(vm.locality, { vm.locality = it }, "City (L)")
            Field(vm.state, { vm.state = it }, "State or province (ST)")
            Field(
                vm.country, { vm.country = it.take(2) }, "Country code (C)",
                error = vm.countryError,
            )
        }
    }
}

@Composable
private fun PasswordCard(vm: MainViewModel) {
    SectionCard("Password", icon = Icons.Outlined.Lock) {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            listOf("Generate" to false, "My own" to true).forEachIndexed { i, (label, custom) ->
                SegmentedButton(
                    selected = vm.customPassword == custom,
                    onClick = { vm.customPassword = custom },
                    shape = SegmentedButtonDefaults.itemShape(i, 2),
                ) { Text(label) }
            }
        }
        if (vm.customPassword) {
            Field(
                vm.password, { vm.password = it }, "Password",
                supporting = "Used for the keystore and the key", error = vm.passwordError, secret = true,
            )
        } else {
            Body("A random 32-character password, used for the keystore and the key. PKCS#12 keystores have one password for both, so KEYSTORE_PASSWORD and KEYSTORE_ALIAS_PASSWORD are the same.")
        }
    }
}

@Composable
private fun ResultCard(vm: MainViewModel, actions: Actions) {
    val keystore = vm.keystore ?: return
    val until = DateFormat.getDateInstance(DateFormat.LONG).format(keystore.certificate.notAfter)
    SectionCard(
        "Your key",
        icon = Icons.Outlined.CheckCircle,
        subtitle = "${keystore.keyType.label} · valid until $until",
    ) {
        Note(
            "The key exists only in this app until you save it, and is gone when the app closes. Back it up first: without it you can never publish an update that installs over your app.",
            Icons.Outlined.WarningAmber, warning = true,
        )
        ValueRow("Alias", keystore.alias, { actions.copy("Alias", keystore.alias, false) })
        ValueRow("Password", keystore.password, { actions.copy("Password", keystore.password, true) }, sensitive = true, hint = "Keystore and key")
        ValueRow("SHA-256", keystore.sha256, { actions.copy("SHA-256 fingerprint", keystore.sha256, false) })
        ValueRow("SHA-1", keystore.sha1, { actions.copy("SHA-1 fingerprint", keystore.sha1, false) }, hint = "For Firebase and Google Sign-In")
        Body("Subject: ${keystore.certificate.subjectX500Principal.name}")
    }
}

@Composable
private fun BitwardenCard(vm: MainViewModel, actions: Actions) {
    SectionCard("Back up", badge = "1", subtitle = "To Bitwarden, as one secure note") {
        Body("Saves a password-protected Bitwarden export: the note holds the ${vm.secretNames.keystore} value, the fields hold passwords, alias and fingerprints. Import it at vault.bitwarden.com → Tools → Import data, format “Bitwarden (json)”, then delete the file. The file password is only for this import.")
        Field(
            vm.filePassword, { vm.filePassword = it }, "File password",
            error = vm.filePasswordError, secret = true,
        )
        Field(
            vm.filePasswordConfirm, { vm.filePasswordConfirm = it }, "Repeat file password",
            error = vm.filePasswordConfirmError, secret = true,
        )
        FilledTonalButton(onClick = actions.saveBitwarden, enabled = vm.canExport, modifier = Modifier.fillMaxWidth()) {
            if (vm.exporting) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
            } else {
                Icon(Icons.Outlined.Save, null, Modifier.size(18.dp))
            }
            Spacer(Modifier.size(8.dp))
            Text("Save Bitwarden export…")
        }
        OutlinedButton(onClick = actions.saveKeystore, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Outlined.Save, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text("Or save the keystore file…")
        }
    }
}

@Composable
private fun SecretsCard(vm: MainViewModel, actions: Actions) {
    val keystore = vm.keystore ?: return
    SectionCard("Add the CI secrets", badge = "2", subtitle = "GitHub → Settings → Secrets and variables → Actions") {
        Body("Create one repository secret per row (“New repository secret”). Copy each value here or from the Bitwarden item.")
        Field(
            vm.repository, { vm.repository = it }, "Repository (optional)",
            supporting = "owner/name or a GitHub URL, to open its secrets page",
        )
        vm.repositoryPath?.let { path ->
            FilledTonalButton(
                onClick = { actions.openUrl("https://github.com/$path/settings/secrets/actions/new") },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text("Open secrets of $path")
            }
        }
        keystore.secrets(vm.secretNames).forEach { secret ->
            ValueRow(
                secret.name, secret.value,
                onCopy = { actions.copy(secret.name, secret.value, secret.sensitive) },
                sensitive = secret.sensitive,
                hint = secret.hint,
                abbreviate = secret.name == vm.secretNames.keystore,
            )
        }
        Expandable("Secret names", summary = "Prefix them, e.g. when one repository signs several apps") {
            Field(
                vm.secretPrefix, { vm.secretPrefix = it.uppercase() }, "Prefix",
                supporting = "e.g. WEAR_ gives WEAR_KEYSTORE, WEAR_KEYSTORE_PASSWORD, …",
                error = vm.prefixError,
            )
        }
        Note(
            "Changing keys means one uninstall: Android only installs an update signed with the same key, so a build signed with this key can't replace one signed with another (e.g. a debug key). Uninstalling also deletes the app's data.",
            Icons.Outlined.Info,
        )
    }
}

@Composable
private fun LocalBuildCard(vm: MainViewModel, actions: Actions) {
    val keystore = vm.keystore ?: return
    SectionCard("Signed builds on your computer", badge = "3", subtitle = "Optional") {
        Body("Put ${keystore.alias}.jks in the repository root and signing.properties next to it. Keep both out of git. KEYSTORE_FILE is relative to the app/ folder, hence the ../.")
        CodeBlock(Snippets.signingProperties(keystore, vm.secretNames).replace(keystore.password, "••••••••"))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(onClick = actions.saveKeystore, modifier = Modifier.weight(1f).widthIn(min = 0.dp)) {
                Icon(Icons.Outlined.Computer, null, Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text(".jks")
            }
            OutlinedButton(onClick = actions.saveSigningProperties, modifier = Modifier.weight(1f).widthIn(min = 0.dp)) {
                Icon(Icons.Outlined.Description, null, Modifier.size(18.dp))
                Spacer(Modifier.size(8.dp))
                Text(".properties")
            }
        }
    }
}
