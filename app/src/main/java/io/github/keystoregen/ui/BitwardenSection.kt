package io.github.keystoregen.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.CloudUpload
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.github.keystoregen.MainViewModel
import io.github.keystoregen.SigningKeystore
import io.github.keystoregen.bitwarden.BitwardenViewModel
import io.github.keystoregen.bitwarden.LoginChallenge
import io.github.keystoregen.bitwarden.Region
import io.github.keystoregen.bitwarden.VaultSave

/** Sign in to Bitwarden and save the keystore as a secure note, straight into the vault. */
@Composable
fun BitwardenVault(vm: MainViewModel, bw: BitwardenViewModel, keystore: SigningKeystore, actions: Actions) {
    var showSignIn by rememberSaveable { mutableStateOf(false) }
    val session = bw.session
    val itemName = vm.bitwardenItemName(keystore)

    if (session == null) {
        Body("Sign in to save the keystore, its passwords and fingerprints as one secure note in your vault. Everything is encrypted on the phone before it's sent, like in the Bitwarden app.")
        Button(onClick = { showSignIn = true }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Outlined.Shield, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text("Sign in to Bitwarden")
        }
    } else {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.Shield, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.size(8.dp))
            Text(
                "${session.email} · ${session.server.label}",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = bw::signOut) { Text("Sign out") }
        }
        val saving = bw.save is VaultSave.Saving
        Button(
            onClick = { bw.saveKeystore(keystore, itemName, vm.secretNames) },
            enabled = !saving && vm.prefixError == null,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (saving) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            } else {
                Icon(Icons.Outlined.CloudUpload, null, Modifier.size(18.dp))
            }
            Spacer(Modifier.size(8.dp))
            Text("Save to Bitwarden")
        }
        Body("As “$itemName”")
        when (val save = bw.save) {
            VaultSave.Idle, VaultSave.Saving -> Unit
            is VaultSave.Saved -> Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.CheckCircle, null, Modifier.size(20.dp))
                        Spacer(Modifier.size(10.dp))
                        Text("Saved to your vault", style = MaterialTheme.typography.titleSmall)
                    }
                    Text(save.itemName, style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { actions.openUrl(webVault(bw)) }) {
                        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(16.dp))
                        Spacer(Modifier.size(6.dp))
                        Text("Open web vault")
                    }
                }
            }
            is VaultSave.Failed -> Note(save.message, Icons.Outlined.ErrorOutline, warning = true)
        }
    }

    if (showSignIn) {
        BitwardenSignInDialog(bw, actions, onDismiss = { showSignIn = false; bw.cancelSignIn() })
        if (bw.session != null) showSignIn = false
    }
}

private fun webVault(bw: BitwardenViewModel) = when (bw.region) {
    Region.US -> "https://vault.bitwarden.com"
    Region.EU -> "https://vault.bitwarden.eu"
    Region.SELF_HOSTED -> bw.selfHostedUrl.trim().trimEnd('/').let { if ("://" in it) it else "https://$it" }
}

@Composable
private fun BitwardenSignInDialog(bw: BitwardenViewModel, actions: Actions, onDismiss: () -> Unit) {
    val challenge = bw.challenge
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.Shield, null) },
        title = { Text(if (challenge == null) "Sign in to Bitwarden" else "Verify it's you") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                when (challenge) {
                    null -> SignInForm(bw, actions)
                    LoginChallenge.NewDevice -> {
                        Field(bw.code, { bw.code = it }, "Verification code", monospace = true)
                    }
                    is LoginChallenge.TwoFactor -> {
                        val supported = challenge.providers.filter { it == 0 || it == 1 }
                        if (supported.size > 1) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                supported.forEach { provider ->
                                    FilterChip(
                                        selected = bw.twoFactorProvider == provider,
                                        onClick = { bw.twoFactorProvider = provider; bw.code = "" },
                                        label = { Text(if (provider == 0) "Authenticator app" else "Email") },
                                    )
                                }
                            }
                        }
                        if (bw.twoFactorProvider == 1) {
                            Body("Bitwarden mails a code to ${challenge.emailHint ?: "your address"}.")
                            TextButton(onClick = bw::sendEmailCode, enabled = !bw.busy) { Text("Send code") }
                        } else {
                            Body("Enter the 6-digit code from your authenticator app.")
                        }
                        Field(bw.code, { bw.code = it }, "Code", monospace = true, number = bw.twoFactorProvider == 0)
                    }
                }
                bw.info?.let { Note(it, Icons.Outlined.Info) }
                if (bw.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                bw.error?.let { Note(it, Icons.Outlined.ErrorOutline, warning = true) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Lock, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.size(8.dp))
                    Text(
                        "Your master password stays on the phone; Bitwarden only gets a hash. The session ends when the app closes.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = bw::signIn, enabled = bw.canSignIn) {
                Text(if (challenge == null) "Sign in" else "Verify")
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun SignInForm(bw: BitwardenViewModel, actions: Actions) {
    SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
        Region.entries.forEachIndexed { i, region ->
            SegmentedButton(
                selected = bw.region == region,
                onClick = { bw.region = region },
                shape = SegmentedButtonDefaults.itemShape(i, Region.entries.size),
            ) { Text(if (region == Region.SELF_HOSTED) "Other" else region.label.substringAfter('.').let { ".$it" }, maxLines = 1) }
        }
    }
    if (bw.region == Region.SELF_HOSTED) {
        Field(bw.selfHostedUrl, { bw.selfHostedUrl = it }, "Server URL", supporting = "e.g. vault.example.com")
    }
    Field(bw.email, { bw.email = it }, "Email")
    Field(bw.masterPassword, { bw.masterPassword = it }, "Master password", secret = true)
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text("Use personal API key", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Switch(checked = bw.useApiKey, onCheckedChange = { bw.useApiKey = it })
    }
    if (bw.useApiKey) {
        Body("Skips two-step login and captchas. Find it at Settings → Security → Keys → View API key. The master password is still needed to unlock the vault.")
        TextButton(onClick = { actions.openUrl("https://bitwarden.com/help/personal-api-key/") }) {
            Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(16.dp))
            Spacer(Modifier.size(6.dp))
            Text("About API keys")
        }
        Field(bw.clientId, { bw.clientId = it }, "client_id", monospace = true)
        Field(bw.clientSecret, { bw.clientSecret = it }, "client_secret", secret = true, monospace = true)
    }
}
