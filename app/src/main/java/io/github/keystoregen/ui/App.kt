package io.github.keystoregen.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.os.PersistableBundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.MenuBook
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.core.net.toUri
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.keystoregen.MainViewModel
import io.github.keystoregen.github.GitHubViewModel
import io.github.keystoregen.importing.ImportViewModel
import kotlinx.coroutines.launch

/** What the screens need from the outside world: clipboard, files, messages. */
class Actions(
    val copy: (label: String, value: String, sensitive: Boolean) -> Unit,
    val saveKeystore: () -> Unit,
    val saveSigningProperties: () -> Unit,
    val saveBitwarden: () -> Unit,
    val openUrl: (String) -> Unit,
    val startIntent: (android.content.Intent) -> Unit,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun App(vm: MainViewModel = viewModel(), gh: GitHubViewModel = viewModel(), imp: ImportViewModel = viewModel()) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var error by remember { mutableStateOf<Throwable?>(null) }
    /** Runs once the user agrees to drop the current key. */
    var pendingReplace by remember { mutableStateOf<(() -> Unit)?>(null) }

    fun message(text: String) {
        scope.launch {
            snackbar.currentSnackbarData?.dismiss()
            snackbar.showSnackbar(text)
        }
    }

    fun write(uri: Uri?, bytes: ByteArray, done: String) {
        if (uri == null) return
        runCatching {
            context.contentResolver.openOutputStream(uri, "wt")!!.use { it.write(bytes) }
        }.onSuccess { message(done) }.onFailure { error = it }
    }

    val keystoreSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        vm.keystore?.let { write(uri, it.bytes, "Keystore saved") }
    }
    val propertiesSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        vm.keystore?.let { write(uri, io.github.keystoregen.Snippets.signingProperties(it, vm.secretNames).toByteArray(), "signing.properties saved") }
    }
    val bitwardenSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) {
            message("Encrypting…")
            vm.exportBitwarden { result ->
                result.onSuccess { write(uri, it, "Bitwarden export saved") }.onFailure { error = it }
            }
        }
    }

    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        runCatching {
            val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
                ?.use { if (it.moveToFirst()) it.getString(0) else null } ?: "file"
            val bytes = context.contentResolver.openInputStream(uri)!!.use { input ->
                // No keystore or vault export comes near this; anything bigger is the wrong file.
                input.readNBytesCompat(MAX_IMPORT_BYTES + 1)
            }
            require(bytes.size <= MAX_IMPORT_BYTES) { "That file is too big for a keystore or Bitwarden export" }
            name to bytes
        }.onSuccess { (name, bytes) -> imp.fileLoaded(name, bytes) }
            .onFailure { imp.fileFailed(it.message ?: it.toString()) }
    }

    val actions = Actions(
        copy = { label, value, sensitive ->
            context.copyToClipboard(label, value, sensitive)
            message("$label copied")
        },
        saveKeystore = { vm.keystore?.let { keystoreSaver.launch("${it.alias}.jks") } },
        saveSigningProperties = { propertiesSaver.launch("signing.properties") },
        saveBitwarden = { vm.keystore?.let { bitwardenSaver.launch("${it.alias}-bitwarden.json") } },
        openUrl = { url ->
            runCatching {
                context.startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, url.toUri()))
            }.onFailure { message("No browser found") }
        },
        startIntent = { intent ->
            runCatching { context.startActivity(intent) }
                .recoverCatching { context.startActivity(android.content.Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS)) }
                .onFailure { message("Couldn't open Settings") }
        },
    )

    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()
    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text(if (tab == 0) "Signing key" else "Setup guide") },
                scrollBehavior = scrollBehavior,
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0,
                    onClick = { tab = 0 },
                    icon = { Icon(if (tab == 0) Icons.Filled.Key else Icons.Outlined.Key, null) },
                    label = { Text("Generate") },
                )
                NavigationBarItem(
                    selected = tab == 1,
                    onClick = { tab = 1 },
                    icon = { Icon(Icons.AutoMirrored.Outlined.MenuBook, null) },
                    label = { Text("Guide") },
                )
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        val modifier = Modifier.padding(padding)
        when (tab) {
            0 -> GenerateScreen(
                vm = vm,
                gh = gh,
                actions = actions,
                imp = imp,
                onGenerate = {
                    val generate = { vm.generate { error = it } }
                    if (vm.keystore != null) pendingReplace = generate else generate()
                },
                onPickImport = {
                    importPicker.launch(arrayOf("*/*"))
                },
                onImport = {
                    val import = {
                        imp.finish { keystore, prefix ->
                            vm.useKeystore(keystore, prefix)
                            gh.dismissUpload()
                            message("Imported ${keystore.alias}")
                        }
                    }
                    if (vm.keystore != null) pendingReplace = import else import()
                },
                modifier = modifier,
            )
            else -> GuideScreen(vm = vm, actions = actions, modifier = modifier)
        }
    }

    pendingReplace?.let { replace ->
        AlertDialog(
            onDismissRequest = { pendingReplace = null },
            title = { Text("Replace the current key?") },
            text = { Text("Unless you saved or backed it up, the current key is lost for good. Apps signed with it can then never be updated.") },
            confirmButton = {
                TextButton(onClick = {
                    pendingReplace = null
                    replace()
                }) { Text("Replace") }
            },
            dismissButton = { TextButton(onClick = { pendingReplace = null }) { Text("Cancel") } },
        )
    }

    error?.let {
        AlertDialog(
            onDismissRequest = { error = null },
            title = { Text("Something went wrong") },
            text = { Text(it.message ?: it.toString()) },
            confirmButton = { TextButton(onClick = { error = null }) { Text("OK") } },
        )
    }
}

private const val MAX_IMPORT_BYTES = 5 * 1024 * 1024

/** InputStream.readNBytes needs API 33; this reads up to [limit] bytes on any version. */
private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (out.size() < limit) {
        val n = read(buffer, 0, minOf(buffer.size, limit - out.size()))
        if (n < 0) break
        out.write(buffer, 0, n)
    }
    return out.toByteArray()
}

/** Sensitive clips are hidden from the clipboard preview on Android 13+. */
private fun Context.copyToClipboard(label: String, value: String, sensitive: Boolean) {
    val clip = ClipData.newPlainText(label, value)
    if (sensitive) {
        clip.description.extras = PersistableBundle().apply {
            // ClipDescription.EXTRA_IS_SENSITIVE, a constant only from API 33 on.
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
    }
    getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}
