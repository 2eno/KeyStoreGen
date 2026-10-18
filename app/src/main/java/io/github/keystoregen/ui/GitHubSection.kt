package io.github.keystoregen.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.OpenInNew
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.ContentCopy
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.UnfoldMore
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.keystoregen.SigningKeystore
import io.github.keystoregen.MainViewModel
import io.github.keystoregen.github.DeviceAuth
import io.github.keystoregen.github.GitHubViewModel
import io.github.keystoregen.github.Upload
import io.github.keystoregen.secrets

/** Sign-in, repository picker and the one-tap upload of all four secrets. */
@Composable
fun GitHubUpload(vm: MainViewModel, gh: GitHubViewModel, keystore: SigningKeystore, actions: Actions) {
    var showSignIn by rememberSaveable { mutableStateOf(false) }
    var showPicker by rememberSaveable { mutableStateOf(false) }
    val login = gh.login
    val repo = vm.repositoryPath

    if (gh.token == null) {
        Body("Sign in to add all four secrets to a repository in one tap, confirmed with your fingerprint, face or screen lock. They are encrypted on the phone with the repository's public key, so only GitHub Actions can read them.")
        Button(onClick = { showSignIn = true }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Outlined.AccountCircle, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text("Sign in with GitHub")
        }
    } else {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.AccountCircle, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.size(8.dp))
            Text(
                if (login != null) "Signed in as $login" else "Signed in",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = gh::signOut) { Text("Sign out") }
        }
        RepoSelector(repo, onClick = { showPicker = true; if (gh.repos.isEmpty()) gh.loadRepos() })

        val upload = gh.upload
        val busy = upload is Upload.Checking || upload is Upload.Uploading
        val context = LocalContext.current
        var authStatus by remember { mutableStateOf(DeviceAuth.status(context)) }
        var authError by remember { mutableStateOf<String?>(null) }
        // The user may set up a screen lock in Settings and come back.
        LifecycleResumeEffect(Unit) {
            authStatus = DeviceAuth.status(context)
            onPauseOrDispose { }
        }
        Button(
            onClick = {
                val target = repo!!
                val secrets = keystore.secrets(vm.secretNames).map { it.name to it.value }
                authError = null
                DeviceAuth.authenticate(
                    context,
                    title = "Add secrets to $target",
                    subtitle = "Confirm it's you to upload the signing key",
                    onSuccess = { gh.uploadSecrets(target, secrets) },
                    onError = { authError = it },
                )
            },
            enabled = repo != null && !busy && vm.prefixError == null && authStatus == DeviceAuth.Status.READY,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Outlined.Fingerprint, null, Modifier.size(18.dp))
            Spacer(Modifier.size(8.dp))
            Text(if (repo != null) "Add 4 secrets to $repo" else "Choose a repository first")
        }
        when (authStatus) {
            DeviceAuth.Status.READY -> Text(
                "You'll confirm with your fingerprint, face or screen lock.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            DeviceAuth.Status.NOT_SET_UP -> {
                Note(
                    "Uploading needs a screen lock or biometrics, so only you can send your signing key to GitHub. Set one up, then come back.",
                    Icons.Outlined.Lock, warning = true,
                )
                FilledTonalButton(onClick = { actions.startIntent(DeviceAuth.setupIntent()) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Set up screen lock")
                }
            }
            DeviceAuth.Status.UNAVAILABLE -> Note(
                "This device can't confirm your identity right now, so uploading is off. Add the secrets by hand below.",
                Icons.Outlined.ErrorOutline, warning = true,
            )
        }
        authError?.let { Note(it, Icons.Outlined.ErrorOutline, warning = true) }
        UploadStatus(upload, total = 4, onOpen = { actions.openUrl("https://github.com/$it/settings/secrets/actions") })
    }

    if (showSignIn) {
        SignInDialog(gh, actions, onDismiss = { showSignIn = false; gh.cancelSignIn() })
        if (gh.token != null) showSignIn = false
    }
    if (showPicker) {
        RepoPickerDialog(gh, onPick = { vm.repository = it; showPicker = false; gh.dismissUpload() }, onDismiss = { showPicker = false })
    }
    (gh.upload as? Upload.ConfirmOverwrite)?.let { confirm ->
        AlertDialog(
            onDismissRequest = gh::dismissUpload,
            icon = { Icon(Icons.Outlined.ErrorOutline, null) },
            title = { Text("Replace existing secrets?") },
            text = {
                Text(
                    "${confirm.repo} already has ${confirm.existing.joinToString()}. Replacing them switches its builds to this new key. " +
                        "Updates signed with it won't install over apps signed with the old key, and the old values can't be recovered from GitHub.",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    gh.uploadSecrets(confirm.repo, keystore.secrets(vm.secretNames).map { it.name to it.value }, overwrite = true)
                }) { Text("Replace") }
            },
            dismissButton = { TextButton(onClick = gh::dismissUpload) { Text("Cancel") } },
        )
    }
}

@Composable
private fun RepoSelector(repo: String?, onClick: () -> Unit) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHighest,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Repository", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(repo ?: "Choose…", style = MaterialTheme.typography.bodyLarge)
            }
            Icon(Icons.Outlined.UnfoldMore, "Choose repository")
        }
    }
}

@Composable
private fun UploadStatus(upload: Upload, total: Int, onOpen: (String) -> Unit) {
    when (upload) {
        Upload.Idle, is Upload.ConfirmOverwrite -> Unit
        Upload.Checking -> Progress("Checking existing secrets…", null)
        is Upload.Uploading -> Progress("Uploading ${upload.done.size + 1} of $total…", upload.done.size / total.toFloat())
        is Upload.Done -> Surface(
            color = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.CheckCircle, null, Modifier.size(20.dp))
                    Spacer(Modifier.size(10.dp))
                    Text("Added to ${upload.repo}", style = MaterialTheme.typography.titleSmall)
                }
                Text(upload.names.joinToString(" · "), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                TextButton(onClick = { onOpen(upload.repo) }, modifier = Modifier.padding(start = 0.dp)) {
                    Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(16.dp))
                    Spacer(Modifier.size(6.dp))
                    Text("View on GitHub")
                }
            }
        }
        is Upload.Failed -> Note(upload.message, Icons.Outlined.ErrorOutline, warning = true)
    }
}

@Composable
private fun Progress(label: String, fraction: Float?) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Body(label)
        if (fraction == null) LinearProgressIndicator(Modifier.fillMaxWidth())
        else LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
    }
}

@Composable
private fun SignInDialog(gh: GitHubViewModel, actions: Actions, onDismiss: () -> Unit) {
    var useToken by rememberSaveable { mutableStateOf(!gh.deviceFlowAvailable) }
    var token by rememberSaveable { mutableStateOf("") }
    val code = gh.deviceCode

    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(Icons.Outlined.AccountCircle, null) },
        title = { Text("Sign in with GitHub") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (!useToken) {
                    if (code == null) {
                        Body("You'll get a code to enter on github.com. The app asks for the “repo” scope, the only one that can write Actions secrets.")
                        if (gh.signingIn) LinearProgressIndicator(Modifier.fillMaxWidth())
                    } else {
                        Body("Enter this code at ${code.verificationUri.removePrefix("https://")}:")
                        Surface(
                            color = MaterialTheme.colorScheme.secondaryContainer,
                            shape = RoundedCornerShape(16.dp),
                            modifier = Modifier.fillMaxWidth().clickable { actions.copy("Code", code.userCode, false) },
                        ) {
                            Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    code.userCode,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 28.sp,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.weight(1f),
                                )
                                Icon(Icons.Outlined.ContentCopy, "Copy code")
                            }
                        }
                        FilledTonalButton(
                            onClick = {
                                actions.copy("Code", code.userCode, false)
                                actions.openUrl(code.verificationUri)
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(18.dp))
                            Spacer(Modifier.size(8.dp))
                            Text("Copy code and open GitHub")
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.size(10.dp))
                            Body("Waiting for you to approve…")
                        }
                    }
                } else {
                    Body("Paste a personal access token. Best is a fine-grained token limited to the repositories you need, with the permission “Secrets: Read and write”.")
                    TextButton(onClick = { actions.openUrl("https://github.com/settings/personal-access-tokens/new") }) {
                        Icon(Icons.AutoMirrored.Outlined.OpenInNew, null, Modifier.size(16.dp))
                        Spacer(Modifier.size(6.dp))
                        Text("Create a fine-grained token")
                    }
                    Field(token, { token = it }, "Token", secret = true, monospace = true)
                    if (gh.signingIn) LinearProgressIndicator(Modifier.fillMaxWidth())
                    if (!gh.deviceFlowAvailable) {
                        Body("This build has no OAuth client ID, so signing in with a code isn't available (see README).")
                    }
                }
                gh.signInError?.let { Note(it, Icons.Outlined.ErrorOutline, warning = true) }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Lock, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.size(8.dp))
                    Text(
                        "The token stays on this phone, encrypted by the Android Keystore.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = {
            if (useToken) {
                TextButton(onClick = { gh.signInWithToken(token) }, enabled = token.isNotBlank() && !gh.signingIn) { Text("Sign in") }
            } else if (code == null) {
                TextButton(onClick = gh::startDeviceFlow, enabled = !gh.signingIn) { Text("Get code") }
            }
        },
        dismissButton = {
            Row {
                if (gh.deviceFlowAvailable) {
                    TextButton(onClick = { gh.cancelSignIn(); useToken = !useToken }) {
                        Text(if (useToken) "Use a code" else "Use a token")
                    }
                }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}

@Composable
private fun RepoPickerDialog(gh: GitHubViewModel, onPick: (String) -> Unit, onDismiss: () -> Unit) {
    var query by rememberSaveable { mutableStateOf("") }
    val filtered = remember(gh.repos, query) {
        gh.repos.filter { it.fullName.contains(query.trim(), ignoreCase = true) }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Repository", modifier = Modifier.weight(1f))
                IconButton(onClick = gh::loadRepos, enabled = !gh.loadingRepos) { Icon(Icons.Outlined.Refresh, "Reload") }
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    leadingIcon = { Icon(Icons.Outlined.Search, null) },
                    placeholder = { Text("Search") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                when {
                    gh.loadingRepos && gh.repos.isEmpty() -> LinearProgressIndicator(Modifier.fillMaxWidth())
                    gh.reposError != null -> Note(gh.reposError!!, Icons.Outlined.ErrorOutline, warning = true)
                    filtered.isEmpty() -> Body(if (gh.repos.isEmpty()) "No repositories you can push to." else "No match.")
                }
                LazyColumn(Modifier.heightIn(max = 380.dp)) {
                    items(filtered, key = { it.fullName }) { repo ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable { onPick(repo.fullName) }
                                .padding(vertical = 12.dp, horizontal = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(repo.fullName.substringAfter('/'), style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    repo.fullName.substringBefore('/') + if (!repo.admin) " · no admin access" else "",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            if (repo.private) {
                                Icon(Icons.Outlined.Lock, "Private", Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                        HorizontalDivider()
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
