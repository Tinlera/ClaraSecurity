package com.clara.security.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.clara.security.MainActivity
import com.clara.security.R
import com.clara.security.data.RootExecutor
import com.clara.security.data.ThreatDatabase
import kotlinx.coroutines.*
import java.io.File

/**
 * CLARA Gerçek Zamanlı Koruma Servisi
 * 
 * Arka planda sürekli çalışır ve tehditleri tespit eder:
 * - Yeni uygulama kurulumlarını izler
 * - Dosya sistemi değişikliklerini izler
 * - Şüpheli aktiviteleri tespit eder
 * - Otomatik müdahale yapar
 */
class RealTimeProtectionService : Service() {
    
    companion object {
        private const val TAG = "ClaraRealTimeProtection"
        private const val CHANNEL_ID = "clara_protection"
        private const val NOTIFICATION_ID = 1001
        
        // Tehlikeli paket isimleri
        private val DANGEROUS_PACKAGES = listOf(
            "com.android.systemupdate",
            "com.system.service",
            "com.update.system",
            "com.flash.player",
            "com.adobe.flash",
            "com.android.vending.billing",
            "com.android.locker",
            "com.security.update"
        )
        
        // Tehlikeli izin kombinasyonları
        private val SPYWARE_PERMISSIONS = listOf(
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS"
        )
        
        var isRunning = false
            private set
    }
    
    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private var packageReceiver: BroadcastReceiver? = null
    private var fileObservers: MutableList<FileObserver> = mutableListOf()
    private var monitoringJob: Job? = null
    
    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "═══════════════════════════════════════════")
        Log.d(TAG, "CLARA REAL-TIME PROTECTION SERVICE STARTED")
        Log.d(TAG, "═══════════════════════════════════════════")
        
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())
        
        // Güvenlik sistemlerini başlat
        serviceScope.launch {
            com.clara.security.security.FirewallManager.initialize(applicationContext)
            com.clara.security.security.DeviceAdminHelper.initialize(applicationContext)
        }
        
        // Koruma sistemlerini başlat
        startPackageMonitoring()
        startFileMonitoring()
        startPeriodicScanning()
        startNetworkMonitoring()
        
        isRunning = true
    }
    
    override fun onDestroy() {
        super.onDestroy()
        Log.w(TAG, "Real-time protection service stopped!")
        
        // Cleanup
        packageReceiver?.let { unregisterReceiver(it) }
        fileObservers.forEach { it.stopWatching() }
        monitoringJob?.cancel()
        serviceScope.cancel()
        
        isRunning = false
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY // Sistem tarafından öldürülürse yeniden başlat
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // UYGULAMA İZLEME
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun startPackageMonitoring() {
        packageReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                val packageName = intent?.data?.schemeSpecificPart ?: return
                
                when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED -> {
                        Log.d(TAG, "New app installed: $packageName")
                        serviceScope.launch {
                            analyzeNewApp(packageName)
                        }
                    }
                    Intent.ACTION_PACKAGE_REPLACED -> {
                        Log.d(TAG, "App updated: $packageName")
                        serviceScope.launch {
                            analyzeNewApp(packageName)
                        }
                    }
                }
            }
        }
        
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        
        registerReceiver(packageReceiver, filter)
        Log.d(TAG, "✓ Package monitoring started")
    }
    
    private suspend fun analyzeNewApp(packageName: String) = withContext(Dispatchers.IO) {
        Log.d(TAG, "Analyzing new app: $packageName")
        
        try {
            val pm = packageManager
            val appInfo = pm.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
            val pkgInfo = pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            
            // 1. Bilinen zararlı paket kontrolü
            if (DANGEROUS_PACKAGES.any { packageName.contains(it, ignoreCase = true) }) {
                handleThreat(
                    type = "MALWARE_APP",
                    description = "Bilinen zararlı uygulama kuruldu: $packageName",
                    severity = 10,
                    action = ThreatAction.QUARANTINE,
                    targetPackage = packageName
                )
                return@withContext
            }
            
            // 2. Spyware izin kontrolü
            val permissions = pkgInfo.requestedPermissions ?: emptyArray()
            val hasAccessibility = permissions.any { it.contains("ACCESSIBILITY") }
            val hasSms = permissions.any { it.contains("SMS") }
            
            if (hasAccessibility && hasSms) {
                handleThreat(
                    type = "SPYWARE_DETECTED",
                    description = "Casus yazılım şüphelisi kuruldu: $packageName (Accessibility + SMS izni)",
                    severity = 9,
                    action = ThreatAction.WARN,
                    targetPackage = packageName
                )
                return@withContext
            }
            
            // 3. Tehlikeli izin sayısı
            val dangerousCount = permissions.count { perm ->
                perm.contains("SMS") || perm.contains("CONTACTS") || 
                perm.contains("CALL_LOG") || perm.contains("CAMERA") ||
                perm.contains("RECORD_AUDIO") || perm.contains("LOCATION")
            }
            
            if (dangerousCount >= 6) {
                handleThreat(
                    type = "SUSPICIOUS_APP",
                    description = "Şüpheli uygulama kuruldu: $packageName ($dangerousCount hassas izin)",
                    severity = 6,
                    action = ThreatAction.WARN,
                    targetPackage = packageName
                )
                return@withContext
            }
            
            // 4. Bilinmeyen kaynak kontrolü (Play Store dışı)
            val installer = pm.getInstallerPackageName(packageName)
            if (installer != "com.android.vending" && installer != "com.google.android.packageinstaller") {
                Log.d(TAG, "App installed from unknown source: $packageName (installer: $installer)")
                // Sadece log, tehdit olarak işaretleme
            }
            
            Log.d(TAG, "App $packageName passed security checks")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to analyze app $packageName", e)
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DOSYA İZLEME
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun startFileMonitoring() {
        val watchPaths = listOf(
            "/sdcard/Download",
            "/sdcard/Downloads",
            "/data/local/tmp"
        )
        
        for (path in watchPaths) {
            val dir = File(path)
            if (dir.exists() && dir.canRead()) {
                val observer = object : FileObserver(dir, CREATE or MOVED_TO) {
                    override fun onEvent(event: Int, path: String?) {
                        if (path == null) return
                        
                        val fullPath = "${dir.absolutePath}/$path"
                        Log.d(TAG, "File event: $fullPath")
                        
                        serviceScope.launch {
                            analyzeNewFile(fullPath)
                        }
                    }
                }
                observer.startWatching()
                fileObservers.add(observer)
                Log.d(TAG, "✓ Watching: $path")
            }
        }
        
        Log.d(TAG, "✓ File monitoring started (${fileObservers.size} directories)")
    }
    
    private suspend fun analyzeNewFile(filePath: String) = withContext(Dispatchers.IO) {
        val file = File(filePath)
        if (!file.exists()) return@withContext
        
        val extension = file.extension.lowercase()
        
        // APK dosyası kontrolü
        if (extension == "apk") {
            Log.d(TAG, "New APK detected: $filePath")
            
            // SHA256 hash kontrolü (root varsa)
            if (RootExecutor.hasRootAccess()) {
                val hash = RootExecutor.execute("sha256sum '$filePath' | cut -d' ' -f1")
                    .getOrDefault("").trim()
                
                // Bilinen zararlı hash'leri kontrol et
                // TODO: Hash veritabanı entegrasyonu
                Log.d(TAG, "APK hash: $hash")
            }
            
            // Büyük APK uyarısı
            if (file.length() > 100 * 1024 * 1024) {
                handleThreat(
                    type = "SUSPICIOUS_FILE",
                    description = "Büyük APK dosyası indirildi: ${file.name} (${file.length() / 1024 / 1024}MB)",
                    severity = 4,
                    action = ThreatAction.WARN
                )
            }
        }
        
        // Executable dosya kontrolü
        if (extension in listOf("sh", "so", "dex", "jar") && filePath.contains("/data/local/tmp")) {
            handleThreat(
                type = "SUSPICIOUS_EXECUTABLE",
                description = "Şüpheli çalıştırılabilir dosya: ${file.name}",
                severity = 7,
                action = ThreatAction.QUARANTINE
            )
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PERİYODİK TARAMA
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun startPeriodicScanning() {
        monitoringJob = serviceScope.launch {
            while (isActive) {
                delay(30 * 60 * 1000L) // Her 30 dakikada bir
                
                Log.d(TAG, "Running periodic security check...")
                
                // Ağ bağlantılarını kontrol et
                checkSuspiciousConnections()
                
                // Sistem bütünlüğü kontrolü
                checkSystemIntegrity()
                
                Log.d(TAG, "Periodic check completed")
            }
        }
        
        Log.d(TAG, "✓ Periodic scanning started (every 30 min)")
    }
    
    private suspend fun checkSuspiciousConnections() = withContext(Dispatchers.IO) {
        if (!RootExecutor.hasRootAccess()) return@withContext
        
        val result = RootExecutor.execute("netstat -tunp 2>/dev/null | grep ESTABLISHED")
        if (result.isFailure) return@withContext
        
        val connections = result.getOrDefault("").lines()
        val suspiciousPorts = listOf(4444, 5555, 6666, 7777, 1337, 31337, 8888)
        
        connections.forEach { line ->
            suspiciousPorts.forEach { port ->
                if (line.contains(":$port ")) {
                    // IP adresini al (Örn: tcp 0 0 192.168.1.5:5555 1.2.3.4:443 ESTABLISHED)
                    // Uzak IP'yi bulmaya çalışıyoruz
                    val parts = line.split("\\s+".toRegex())
                    val remoteAddress = parts.find { it.contains(":") && !it.startsWith("0.0.0.0") && !it.startsWith("::") && !it.startsWith("127.0.0.1") }
                    val remoteIp = remoteAddress?.substringBefore(":")
                    
                    handleThreat(
                        type = "SUSPICIOUS_CONNECTION",
                        description = "Şüpheli ağ bağlantısı tespit edildi (port $port) -> $remoteIp",
                        severity = 8,
                        action = ThreatAction.BLOCK,
                        targetIp = remoteIp
                    )
                }
            }
        }
    }
    
    private suspend fun checkSystemIntegrity() = withContext(Dispatchers.IO) {
        if (!RootExecutor.hasRootAccess()) return@withContext
        
        // SELinux kontrolü
        val selinux = RootExecutor.execute("getenforce").getOrDefault("").trim()
        if (selinux.lowercase() == "permissive") {
            Log.w(TAG, "WARNING: SELinux is permissive")
        }
        
        // /system değişiklik kontrolü
        val systemModified = RootExecutor.execute("stat /system/app 2>/dev/null | grep Modify")
            .getOrDefault("")
        Log.d(TAG, "System check: $systemModified")
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // AĞ İZLEME
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun startNetworkMonitoring() {
        serviceScope.launch {
            while (isActive) {
                delay(5 * 60 * 1000L) // Her 5 dakikada bir
                
                if (RootExecutor.hasRootAccess()) {
                    checkSuspiciousConnections()
                }
            }
        }
        
        Log.d(TAG, "✓ Network monitoring started (every 5 min)")
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // TEHDİT YÖNETİMİ
    // ═══════════════════════════════════════════════════════════════════════════
    
    enum class ThreatAction {
        WARN,       // Sadece bildirim
        BLOCK,      // Engelle (Firewall)
        QUARANTINE, // Karantinaya al
        UNINSTALL   // Kaldır
    }
    
    private suspend fun handleThreat(
        type: String,
        description: String,
        severity: Int,
        action: ThreatAction,
        targetPackage: String? = null,
        targetFile: String? = null,
        targetIp: String? = null // YENİ: IP engelleme için
    ) = withContext(Dispatchers.IO) {
        // ... (Loglama aynı kalacak) ...
        
        Log.w(TAG, "OTONOM RESPONSE INITIATED: $action")
        
        // 1. Veritabanına kaydet
        ThreatDatabase.saveThreat(
            context = this@RealTimeProtectionService,
            type = type,
            source = "RealTimeProtection",
            description = description,
            severity = severity
        )
        
        // 2. Bildirim gönder
        sendThreatNotification(type, description, severity)
        
        // 3. GERÇEK OTONOM MÜDAHALE
        when (action) {
            ThreatAction.QUARANTINE -> {
                if (targetFile != null && RootExecutor.hasRootAccess()) {
                    quarantineFile(targetFile)
                    Log.i(TAG, "✓ File quarantined autonomously")
                }
                if (targetPackage != null && severity >= 9) {
                    disableApp(targetPackage)
                    Log.i(TAG, "✓ App disabled autonomously")
                }
            }
            ThreatAction.BLOCK -> {
                if (targetIp != null && RootExecutor.hasRootAccess()) {
                    // Firewall ile IP engelleme
                    com.clara.security.security.FirewallManager.blockIp(targetIp)
                    Log.i(TAG, "✓ Network connection blocked autonomously: $targetIp")
                } else if (targetPackage != null) {
                    // Uygulamanın internetini kes (UID bulma gerekli, şimdilik disable)
                    disableApp(targetPackage)
                }
            }
            ThreatAction.UNINSTALL -> {
                if (targetPackage != null && RootExecutor.hasRootAccess()) {
                    uninstallApp(targetPackage)
                    Log.i(TAG, "✓ App uninstalled autonomously")
                }
            }
            ThreatAction.WARN -> {
                // Sadece bildirim
            }
        }
    }
    
    private suspend fun quarantineFile(filePath: String) = withContext(Dispatchers.IO) {
        val fileName = File(filePath).name
        val quarantinePath = "/data/clara/quarantine/${System.currentTimeMillis()}_$fileName"
        
        val result = RootExecutor.execute("mv '$filePath' '$quarantinePath' && chmod 000 '$quarantinePath'")
        if (result.isSuccess) {
            Log.d(TAG, "File quarantined: $filePath")
        }
    }
    
    private suspend fun disableApp(packageName: String) = withContext(Dispatchers.IO) {
        val result = RootExecutor.execute("pm disable-user $packageName")
        if (result.isSuccess) {
            Log.d(TAG, "App disabled: $packageName")
        }
    }
    
    private suspend fun uninstallApp(packageName: String) = withContext(Dispatchers.IO) {
        val result = RootExecutor.execute("pm uninstall $packageName")
        if (result.isSuccess) {
            Log.d(TAG, "App uninstalled: $packageName")
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // BİLDİRİMLER
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CLARA Gerçek Zamanlı Koruma",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Arka planda güvenlik izleme"
                setShowBadge(false)
            }
            
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CLARA Koruma Aktif")
            .setContentText("Gerçek zamanlı koruma çalışıyor")
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }
    
    private fun sendThreatNotification(type: String, description: String, severity: Int) {
        val channelId = "clara_threats"
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "CLARA Tehdit Bildirimleri",
                if (severity >= 7) NotificationManager.IMPORTANCE_HIGH else NotificationManager.IMPORTANCE_DEFAULT
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        
        val icon = when {
            severity >= 8 -> android.R.drawable.ic_dialog_alert
            severity >= 5 -> android.R.drawable.ic_dialog_info
            else -> android.R.drawable.ic_menu_help
        }
        
        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("⚠️ Tehdit Tespit Edildi: $type")
            .setContentText(description)
            .setSmallIcon(icon)
            .setPriority(if (severity >= 7) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
