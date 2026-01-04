package com.clara.security.ui.screens

import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import coil.compose.rememberAsyncImagePainter
import com.clara.security.data.ClaraConnection
import com.clara.security.model.AppInfo
import com.clara.security.security.SecurityPreferences
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * App Lock Yönetim Ekranı
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppLockScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

    // Gerçek verileri ClaraConnection'dan topla
    val installedApps by connection.installedApps.collectAsState()
    val lockedApps by connection.lockedApps.collectAsState()
    val appLockEnabled by SecurityPreferences.appLockEnabled.collectAsState()

    var showPinDialog by remember { mutableStateOf(false) }
    var showAppSelector by remember { mutableStateOf(false) }
    var masterPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        connection.loadInstalledApps()
        connection.loadLockedApps()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Uygulama Kilidi") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Geri")
                    }
                },
                actions = {
                    IconButton(onClick = { showPinDialog = true }) {
                        Icon(Icons.Default.Key, contentDescription = "PIN Değiştir")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAppSelector = true },
                containerColor = CLARAPrimary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Uygulama Ekle")
            }
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            // Ana açma/kapama anahtarı
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .background(MaterialTheme.colorScheme.surfaceVariant, RoundedCornerShape(16.dp))
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("Uygulama Kilidi Aktif", style = MaterialTheme.typography.titleMedium)
                Switch(
                    checked = appLockEnabled,
                    onCheckedChange = { SecurityPreferences.setAppLockEnabled(it) }
                )
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                item {
                    Text(
                        "Kilitli Uygulamalar (${lockedApps.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.padding(top = 8.dp, bottom = 8.dp)
                    )
                }

                items(lockedApps, key = { it.packageName }) { app ->
                    val appInfo = installedApps.find { it.packageName == app.packageName }
                    LockedAppCard(
                        appName = app.appName,
                        packageName = app.packageName,
                        isLocked = true,
                        onToggle = { enabled ->
                            scope.launch {
                                connection.setAppLocked(app.packageName, enabled)
                            }
                        }
                    )
                }

                if (lockedApps.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Icon(
                                    Icons.Default.LockOpen,
                                    contentDescription = null,
                                    modifier = Modifier.size(48.dp),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(Modifier.height(8.dp))
                                Text(
                                    "Henüz kilitli uygulama yok",
                                    style = MaterialTheme.typography.bodyLarge,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAppSelector) {
        AppSelectorDialog(
            installedApps = installedApps,
            lockedApps = lockedApps,
            onDismiss = { showAppSelector = false },
            onAppSelected = {
                scope.launch {
                    connection.setAppLocked(it.packageName, true)
                }
            }
        )
    }

    if (showPinDialog) {
        AlertDialog(
            onDismissRequest = { showPinDialog = false },
            title = { Text("Master PIN Ayarla") },
            text = {
                Column {
                    OutlinedTextField(
                        value = masterPin,
                        onValueChange = { if (it.length <= 6) masterPin = it },
                        label = { Text("Yeni PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirmPin,
                        onValueChange = { if (it.length <= 6) confirmPin = it },
                        label = { Text("PIN Tekrar") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth(),
                        isError = masterPin != confirmPin
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (masterPin == confirmPin && masterPin.length >= 4) {
                            SecurityPreferences.setAppLockPin(masterPin)
                            showPinDialog = false
                            masterPin = ""
                            confirmPin = ""
                        }
                    },
                    enabled = masterPin == confirmPin && masterPin.length >= 4
                ) {
                    Text("Kaydet")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false }) {
                    Text("İptal")
                }
            }
        )
    }
}

@Composable
fun AppSelectorDialog(
    installedApps: List<AppInfo>,
    lockedApps: List<com.clara.security.model.LockedApp>,
    onDismiss: () -> Unit,
    onAppSelected: (AppInfo) -> Unit
) {
    val notLockedApps = installedApps.filterNot { app -> lockedApps.any { it.packageName == app.packageName } }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp)
        ) {
            LazyColumn(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item { 
                    Text("Kilitlenecek Uygulamayı Seç", style = MaterialTheme.typography.titleLarge, modifier = Modifier.padding(bottom = 8.dp)) 
                }
                items(notLockedApps, key = { it.packageName }) { app ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onAppSelected(app); onDismiss() }
                            .padding(vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // App icon
                        val pm = LocalContext.current.packageManager
                        val icon = try { pm.getApplicationIcon(app.packageName) } catch (e: PackageManager.NameNotFoundException) { null }
                        Image(
                            painter = rememberAsyncImagePainter(model = icon),
                            contentDescription = null,
                            modifier = Modifier.size(40.dp)
                        )
                        Spacer(Modifier.width(16.dp))
                        Text(app.appName, style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
        }
    }
}

@Composable
fun LockedAppCard(
    appName: String,
    packageName: String,
    isLocked: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // App icon
            val pm = LocalContext.current.packageManager
            val icon = try { pm.getApplicationIcon(packageName) } catch (e: PackageManager.NameNotFoundException) { null }
            Image(
                painter = rememberAsyncImagePainter(model = icon),
                contentDescription = null,
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
            )
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    appName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Switch(
                checked = isLocked,
                onCheckedChange = onToggle
            )
        }
    }
}
