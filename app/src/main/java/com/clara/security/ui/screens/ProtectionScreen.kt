package com.clara.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.security.SecurityPreferences
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * Koruma Ekranı
 * Güvenlik modüllerini yönetir
 */
@Composable
fun ProtectionScreen(
    connection: ClaraConnection,
    onNavigateToAppLock: () -> Unit = {},
    onNavigateToTrackers: () -> Unit = {},
    onNavigateToTrustEngine: () -> Unit = {},
    onNavigateToWifiAudit: () -> Unit = {},
    onNavigateToFirewall: () -> Unit = {},
    onNavigateToVpn: () -> Unit = {}
) {
    val scope = rememberCoroutineScope()

    // Koruma modülleri durumlarını SecurityPreferences'dan topla
    val smsProtection by SecurityPreferences.smsScanEnabled.collectAsState()
    val fileProtection by SecurityPreferences.fileScanEnabled.collectAsState()
    val networkProtection by SecurityPreferences.networkMonitorEnabled.collectAsState()
    val trackerBlocking by SecurityPreferences.trackerBlockEnabled.collectAsState()
    val appLock by SecurityPreferences.appLockEnabled.collectAsState()
    val rootHider by SecurityPreferences.rootHiderEnabled.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Güvenlik Modülleri
        item {
            Text(
                "Güvenlik Modülleri",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.Message,
                title = "SMS Koruma",
                description = "Phishing ve spam SMS\'leri tespit eder",
                enabled = smsProtection,
                onToggle = { SecurityPreferences.setSmsScanEnabled(it) }
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.Folder,
                title = "Dosya Koruma",
                description = "Zararlı dosyaları tarar ve engeller",
                enabled = fileProtection,
                onToggle = { SecurityPreferences.setFileScanEnabled(it) }
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.Wifi,
                title = "Ağ İzleme",
                description = "Şüpheli ağ trafiğini izler",
                enabled = networkProtection,
                onToggle = { SecurityPreferences.setNetworkMonitorEnabled(it) }
            )
        }

        // Gizlilik Modülleri
        item {
            Spacer(Modifier.height(8.dp))
            Text(
                "Gizlilik Modülleri",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.Block,
                title = "Tracker Engelleme",
                description = "Reklam ve izleyici domainleri engeller",
                enabled = trackerBlocking,
                onToggle = { SecurityPreferences.setTrackerBlockEnabled(it) },
                onClick = onNavigateToTrackers
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.Lock,
                title = "Uygulama Kilidi",
                description = "Hassas uygulamaları PIN ile korur",
                enabled = appLock,
                onToggle = { SecurityPreferences.setAppLockEnabled(it) },
                onClick = onNavigateToAppLock
            )
        }

        item {
            ProtectionCard(
                icon = Icons.Default.VisibilityOff,
                title = "Root Gizleyici",
                description = "Root\'u belirli uygulamalardan gizler",
                enabled = rootHider,
                onToggle = { SecurityPreferences.setRootHiderEnabled(it) }
            )
        }

        // Gelişmiş Güvenlik
        item {
            Spacer(Modifier.height(8.dp))
            Text(
                "Gelişmiş Güvenlik",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }

        item {
            FeatureCard(
                icon = Icons.Default.VerifiedUser,
                title = "Trust Engine",
                description = "Uygulama güven puanları ve karantina yönetimi",
                onClick = onNavigateToTrustEngine
            )
        }

        item {
            FeatureCard(
                icon = Icons.Default.Wifi,
                title = "WiFi Güvenlik Taraması",
                description = "Bağlı ağın güvenlik analizi",
                onClick = onNavigateToWifiAudit
            )
        }

        item {
            FeatureCard(
                icon = Icons.Default.Security,
                title = "Network Firewall",
                description = "Uygulama bazlı ağ erişim kontrolü",
                onClick = onNavigateToFirewall
            )
        }

        item {
            FeatureCard(
                icon = Icons.Default.VpnKey,
                title = "VPN (WireGuard)",
                description = "Mullvad VPN ile güvenli bağlantı",
                onClick = onNavigateToVpn
            )
        }

        // Hızlı İşlemler
        item {
            Spacer(Modifier.height(8.dp))
            Text(
                "Hızlı İşlemler",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }

        item {
            val context = androidx.compose.ui.platform.LocalContext.current
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Search,
                    title = "Tam Tarama",
                    onClick = {
                        scope.launch { 
                            android.widget.Toast.makeText(context, "Tam tarama başlatıldı...", android.widget.Toast.LENGTH_SHORT).show()
                            connection.startScan()
                            android.widget.Toast.makeText(context, "Tarama tamamlandı!", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                )
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Refresh,
                    title = "Blocklist Güncelle",
                    onClick = {
                        scope.launch { 
                            android.widget.Toast.makeText(context, "Blocklist güncelleniyor...", android.widget.Toast.LENGTH_SHORT).show()
                            connection.updateBlocklists()
                            android.widget.Toast.makeText(context, "Blocklist güncellendi!", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                )
            }
        }

        item {
            val context = androidx.compose.ui.platform.LocalContext.current
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.CleaningServices,
                    title = "Karantina Temizle",
                    onClick = {
                        scope.launch { 
                            android.widget.Toast.makeText(context, "Karantina temizleniyor...", android.widget.Toast.LENGTH_SHORT).show()
                            connection.clearQuarantine()
                            android.widget.Toast.makeText(context, "Karantina temizlendi!", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                )
                QuickActionCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.RestartAlt,
                    title = "Servisleri Yeniden Başlat",
                    onClick = {
                        scope.launch {
                            android.widget.Toast.makeText(context, "Servisler yeniden başlatılıyor...", android.widget.Toast.LENGTH_SHORT).show()
                            connection.stopDaemon("orchestrator")
                            kotlinx.coroutines.delay(500)
                            connection.startDaemon("orchestrator")
                            android.widget.Toast.makeText(context, "Servisler yeniden başlatıldı!", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                )
            }
        }
    }
}

@Composable
fun ProtectionCard(
    icon: ImageVector,
    title: String,
    description: String,
    enabled: Boolean,
    onToggle: (Boolean) -> Unit,
    onClick: (() -> Unit)? = null
) {
    Card(
        onClick = { onClick?.invoke() },
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        enabled = onClick != null,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(
                        if (enabled) CLARAPrimary.copy(alpha = 0.1f)
                        else MaterialTheme.colorScheme.surface
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = if (enabled) CLARAPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
            }

            Spacer(Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Switch(
                checked = enabled,
                onCheckedChange = onToggle,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = MaterialTheme.colorScheme.primary,
                    checkedTrackColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        }
    }
}

@Composable
fun QuickActionCard(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    title: String,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = modifier,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.height(8.dp))
            Text(
                title,
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

@Composable
fun FeatureCard(
    icon: ImageVector,
    title: String,
    description: String,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
            }

            Spacer(Modifier.width(16.dp))

            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Icon(
                Icons.Default.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
