package io.github.keystoregen.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Download
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.FileOpen
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.github.keystoregen.importing.ImportSource
import io.github.keystoregen.importing.ImportViewModel

/** Import an existing keystore from a file, a Bitwarden export, or pasted base64. */
@Composable
fun ImportCard(imp: ImportViewModel, onPickFile: (ImportSource) -> Unit, onFinish: () -> Unit) {
    SectionCard("Import a keystore", icon = Icons.Outlined.Download, subtitle = "Use a key you already have") {
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            ImportSource.entries.forEachIndexed { i, source ->
                SegmentedButton(
                    selected = imp.source == source,
                    onClick = { imp.selectSource(source) },
                    shape = SegmentedButtonDefaults.itemShape(i, ImportSource.entries.size),
                ) { Text(source.label, maxLines = 1) }
            }
        }

        when (imp.source) {
            ImportSource.FILE -> {
                Body("A .jks, .keystore or .p12 file, PKCS#12 or the older JKS format. It is used as it is, byte for byte.")
                PickButton(imp.fileName, "Choose keystore file…") { onPickFile(ImportSource.FILE) }
            }
            ImportSource.BITWARDEN -> {
                Body("A Bitwarden JSON export with the keystore (base64) in an item's notes, like the backup this app saves. In Bitwarden: Tools → Export vault → “.json (Password protected)” or “.json”.")
                PickButton(imp.fileName, "Choose Bitwarden export…") { onPickFile(ImportSource.BITWARDEN) }
                if (imp.needsFilePassword) {
                    Field(imp.filePassword, { imp.filePassword = it }, "File password", secret = true)
                    BusyButton("Decrypt", Icons.Outlined.LockOpen, imp.busy, enabled = imp.filePassword.isNotEmpty(), onClick = imp::readBitwarden)
                }
                if (imp.items.size > 1) {
                    Text("Items with a keystore", style = MaterialTheme.typography.labelLarge)
                    Column {
                        imp.items.forEach { item ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .selectable(imp.selectedItem == item, role = Role.RadioButton) { imp.selectItem(item) }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = imp.selectedItem == item, onClick = null)
                                Spacer(Modifier.size(12.dp))
                                Text(item.itemName, style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                    }
                } else {
                    imp.selectedItem?.let { Body("Item: ${it.itemName}") }
                }
            }
            ImportSource.PASTE -> {
                Body("Paste the keystore as base64, e.g. copied from a Bitwarden note or wherever you keep the KEYSTORE secret.")
                OutlinedTextField(
                    value = imp.pasted,
                    onValueChange = { imp.pasted = it },
                    label = { Text("Base64 keystore") },
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier.fillMaxWidth(),
                )
                FilledTonalButton(onClick = imp::usePasted, enabled = imp.pasted.isNotBlank(), modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Outlined.ContentPaste, null, Modifier.size(18.dp))
                    Spacer(Modifier.size(8.dp))
                    Text("Read keystore")
                }
            }
        }

        if (imp.hasKeystore) {
            imp.format?.let { Body("$it keystore found.") }
            Field(imp.storePassword, { imp.storePassword = it }, "Keystore password", secret = true)
            if (imp.entries.isEmpty()) {
                BusyButton("Unlock", Icons.Outlined.LockOpen, imp.busy, enabled = imp.storePassword.isNotEmpty(), onClick = { imp.unlock() })
            } else {
                if (imp.entries.size > 1) {
                    Text("Key", style = MaterialTheme.typography.labelLarge)
                    Column {
                        imp.entries.forEach { entry ->
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .selectable(imp.alias == entry.alias, role = Role.RadioButton) { imp.alias = entry.alias }
                                    .padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                RadioButton(selected = imp.alias == entry.alias, onClick = null)
                                Spacer(Modifier.size(12.dp))
                                Column {
                                    Text(entry.alias, style = MaterialTheme.typography.bodyLarge)
                                    Text(
                                        entry.certificate.subjectX500Principal.name,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                }
                            }
                        }
                    }
                } else {
                    Body("Key: ${imp.alias}")
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("Different key password", style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
                    Switch(checked = imp.separateKeyPassword, onCheckedChange = { imp.separateKeyPassword = it })
                }
                if (imp.separateKeyPassword) {
                    Field(imp.keyPassword, { imp.keyPassword = it }, "Key password", secret = true)
                }
                BusyButton("Use this key", Icons.Outlined.Download, imp.busy, enabled = imp.alias != null, filled = true, onClick = onFinish)
            }
        }

        imp.error?.let { Note(it, Icons.Outlined.ErrorOutline, warning = true) }
        Note(
            "Importing reads the keystore into memory only. To upload or back it up, use the steps below once it's imported.",
            Icons.Outlined.Info,
        )
    }
}

@Composable
private fun PickButton(fileName: String?, label: String, onClick: () -> Unit) {
    if (fileName != null) {
        Surface(
            color = MaterialTheme.colorScheme.surfaceContainerHighest,
            shape = RoundedCornerShape(12.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.FileOpen, null, Modifier.size(20.dp))
                Spacer(Modifier.size(12.dp))
                Text(fileName, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f))
            }
        }
    }
    OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Outlined.FileOpen, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text(if (fileName == null) label else "Choose another file…")
    }
}

@Composable
private fun BusyButton(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    busy: Boolean,
    enabled: Boolean,
    filled: Boolean = false,
    onClick: () -> Unit,
) {
    val content: @Composable () -> Unit = {
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Icon(icon, null, Modifier.size(18.dp))
        Spacer(Modifier.size(8.dp))
        Text(label)
    }
    val modifier = Modifier.fillMaxWidth().height(48.dp)
    if (filled) {
        Button(onClick = onClick, enabled = enabled && !busy, modifier = modifier) { content() }
    } else {
        FilledTonalButton(onClick = onClick, enabled = enabled && !busy, modifier = modifier) { content() }
    }
}

