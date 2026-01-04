package com.clara.security.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.model.DaemonStatus
import com.clara.security.model.SecurityStats
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * Dashboard Ekranı
 * Ana güvenlik durumu ve istatistikleri gösterir
 */
@Composable
fun DashboardScreen(connection: ClaraConnection) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val scope = rememberCoroutineScope()
    val daemonStatuses by connection.daemonStatuses.collectAsState()
    val stats by connection.stats.collectAsState()
    val isConnected by connection.isConnected.collectAsState()
    val isScanning by connection.isScanning.collectAsState()
    
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Ana Güvenlik Durumu Kartı
        item {
            SecurityStatusCard(
                isProtected = isConnected && daemonStatuses.count { it.isRunning } >= 3,
                threatsToday = stats.threatsToday,
                isScanning = isScanning,
                onScanClick = {
                    scope.launch { 
                        android.widget.Toast.makeText(context, "Tarama başlatılıyor...", android.widget.Toast.LENGTH_SHORT).show()
                        val result = connection.startScan()
                        if (result) {
                            android.widget.Toast.makeText(context, "Tarama tamamlandı!", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                }
            )
        }
        
        // Gerçek Zamanlı Koruma Durumu
        item {
            RealTimeProtectionCard()
        }
        
        // İstatistik Kartları
        item {
            Text(
                "Özet İstatistikler",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
        
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Warning,
                    value = stats.totalThreats.toString(),
                    label = "Toplam Tehdit",
                    color = CLARAError
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Block,
                    value = stats.trackersBlocked.toString(),
                    label = "Tracker Engeli",
                    color = CLARASecondary
                )
            }
        }
        
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Message,
                    value = stats.smsScanned.toString(),
                    label = "SMS Tarandı",
                    color = CLARATertiary
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    icon = Icons.Default.Folder,
                    value = stats.filesScanned.toString(),
                    label = "Dosya Tarandı",
                    color = CLARASuccess
                )
            }
        }
        
        // Daemon Durumları
        item {
            Text(
                "Servis Durumu",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
        
        items(daemonStatuses) { status ->
            DaemonStatusCard(
                status = status,
                onToggle = {
                    scope.launch {
                        if (status.isRunning) {
                            connection.stopDaemon(status.name)
                        } else {
                            connection.startDaemon(status.name)
                        }
                    }
                }
            )
        }
        
        // Yenileme butonu
        item {
            Button(
                onClick = {
                    scope.launch {
                        connection.checkDaemonStatuses()
                        connection.loadStats()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Durumu Yenile")
            }
        }
    }
}

@Composable
fun SecurityStatusCard(
    isProtected: Boolean,
    threatsToday: Int,
    isScanning: Boolean = false,
    onScanClick: () -> Unit
) {
    val gradientColors = if (isProtected) {
        listOf(Color(0xFF22C55E), Color(0xFF16A34A))
    } else {
        listOf(Color(0xFFEF4444), Color(0xFFDC2626))
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Brush.linearGradient(gradientColors))
                .padding(24.dp)
        ) {
            Column {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .clip(CircleShape)
                            .background(Color.White.copy(alpha = 0.2f)),
                        contentAlignment = Alignment.Center
                    ) {
                        if (isScanning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(36.dp),
                                color = Color.White,
                                strokeWidth = 3.dp
                            )
                        } else {
                            Icon(
                                if (isProtected) Icons.Default.Shield else Icons.Default.Warning,
                                contentDescription = null,
                                tint = Color.White,
                                modifier = Modifier.size(36.dp)
                            )
                        }
                    }
                    
                    Spacer(Modifier.width(16.dp))
                    
                    Column {
                        Text(
                            if (isScanning) "Taranıyor..." else if (isProtected) "Korumalı" else "Risk Altında",
                            style = MaterialTheme.typography.headlineMedium,
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            if (isScanning) 
                                "Sistem taranıyor, lütfen bekleyin..."
                            else if (threatsToday > 0) 
                                "Bugün $threatsToday tehdit tespit edildi" 
                            else 
                                "Hiçbir tehdit tespit edilmedi",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.White.copy(alpha = 0.9f)
                        )
                    }
                }
                
                Spacer(Modifier.height(16.dp))
                
                Button(
                    onClick = onScanClick,
                    enabled = !isScanning,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color.White,
                        contentColor = gradientColors[0],
                        disabledContainerColor = Color.White.copy(alpha = 0.5f)
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    if (isScanning) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = gradientColors[0],
                            strokeWidth = 2.dp
                        )
                        Spacer(Modifier.width(8.dp))
                        Text("Taranıyor...", fontWeight = FontWeight.SemiBold)
                    } else {
                        Icon(Icons.Default.Search, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Tarama Başlat", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }
    }
}

@Composable
fun StatCard(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    value: String,
    label: String,
    color: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp)
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
                tint = color,
                modifier = Modifier.size(28.dp)
            )
            Spacer(Modifier.height(8.dp))
            Text(
                value,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold
            )
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun DaemonStatusCard(
    status: DaemonStatus,
    onToggle: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .clip(CircleShape)
                    .background(if (status.isRunning) CLARASuccess else CLARAError)
            )
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    status.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    if (status.isRunning) "Çalışıyor (PID: ${status.pid})" else "Durduruldu",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Switch(
                checked = status.isRunning,
                onCheckedChange = { onToggle() }
            )
        }
    }
}

@Composable
fun RealTimeProtectionCard() {
    val isActive = com.clara.security.service.RealTimeProtectionService.isRunning
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isActive) 
                Color(0xFF1B5E20).copy(alpha = 0.1f) 
            else 
                Color(0xFFB71C1C).copy(alpha = 0.1f)
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
                    .clip(CircleShape)
                    .background(
                        if (isActive) Color(0xFF4CAF50) else Color(0xFFF44336)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    if (isActive) Icons.Default.Shield else Icons.Outlined.Shield,
                    contentDescription = null,
                    tint = Color.White,
                    modifier = Modifier.size(28.dp)
                )
            }
            
            Spacer(Modifier.width(16.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "Gerçek Zamanlı Koruma",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    if (isActive) "✓ Aktif - Arka planda izleniyor" else "✗ Devre dışı",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (isActive) Color(0xFF4CAF50) else Color(0xFFF44336)
                )
                if (isActive) {
                    Text(
                        "Uygulama kurulumları • Dosya değişiklikleri • Ağ izleme",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}
