package com.clara.security.data

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import android.util.Log
import com.clara.security.ipc.DaemonIpcClient
import com.clara.security.model.*
import com.clara.security.security.SecurityPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

/**
 * CLARA Bağlantı Yöneticisi - GERÇEK GÜVENLİK SİSTEMİ
 *
 * Root erişimi ile tam sistem kontrolü:
 * - Dosya sistemi taraması
 * - Uygulama analizi
 * - Ağ izleme
 * - Tehdit tespiti ve karantina
 * - Native daemon iletişimi
 */
class ClaraConnection(private val _context: Context) {
    companion object {
        private const val TAG = "ClaraConnection"
        private const val LOCKED_APPS_PREF_KEY = "locked_apps_list"
        
        // Bilinen zararlı SHA256 hash'leri (gerçek malware imzaları)
        private val KNOWN_MALWARE_HASHES = setOf(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // Örnek
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        )
        
        // Tehlikeli izinler
        private val DANGEROUS_PERMISSIONS = listOf(
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.READ_PHONE_STATE"
        )
        
        // Bilinen zararlı paket isimleri
        private val KNOWN_MALWARE_PACKAGES = listOf(
            "com.android.providers.downloadsui", // Sahte indir yöneticisi
            "com.android.systemupdate", // Sahte sistem güncellemesi
            "com.update.systemsoftware",
            "com.flash.player", // Sahte Flash
            "com.adobe.flashplayer",
            "com.android.vending.billing", // Sahte Google Play
            "com.system.service",
            "com.android.locker"
        )
        
        // Tehlikeli dosya uzantıları
        private val DANGEROUS_EXTENSIONS = listOf(
            "apk", "dex", "jar", "so", "sh", "bat", "exe", "bin"
        )
        
        // Taranacak dizinler (root ile)
        private val SCAN_DIRECTORIES = listOf(
            "/sdcard/Download",
            "/sdcard/Downloads",
            "/sdcard/DCIM",
            "/sdcard/Documents",
            "/sdcard/WhatsApp/Media",
            "/sdcard/Telegram",
            "/data/local/tmp",
            "/sdcard/Android/data"
        )
    }

    val context: Context get() = _context

    // ═══════════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════════

    enum class ConnectionMode {
        FULL,       // Daemon + Root + AI
        ROOT_ONLY,  // Root + AI (daemon yok)
        NO_ROOT     // Sadece yerel (sınırlı özellikler)
    }

    private val _connectionMode = MutableStateFlow(ConnectionMode.NO_ROOT)
    val connectionMode: StateFlow<ConnectionMode> = _connectionMode.asStateFlow()

    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()

    private val _hasRoot = MutableStateFlow(false)
    val hasRoot: StateFlow<Boolean> = _hasRoot.asStateFlow()

    private val _daemonStatuses = MutableStateFlow<List<DaemonStatus>>(emptyList())
    val daemonStatuses: StateFlow<List<DaemonStatus>> = _daemonStatuses.asStateFlow()

    private val _recentThreats = MutableStateFlow<List<ThreatInfo>>(emptyList())
    val recentThreats: StateFlow<List<ThreatInfo>> = _recentThreats.asStateFlow()

    private val _stats = MutableStateFlow(SecurityStats())
    val stats: StateFlow<SecurityStats> = _stats.asStateFlow()

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanProgress = MutableStateFlow(0)
    val scanProgress: StateFlow<Int> = _scanProgress.asStateFlow()

    private val _installedApps = MutableStateFlow<List<AppInfo>>(emptyList())
    val installedApps: StateFlow<List<AppInfo>> = _installedApps.asStateFlow()

    private val _lockedApps = MutableStateFlow<List<LockedApp>>(emptyList())
    val lockedApps: StateFlow<List<LockedApp>> = _lockedApps.asStateFlow()

    // ═══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════

    suspend fun initialize() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Initializing CLARA Security System...")

        // Root kontrolü
        val hasRootAccess = RootExecutor.hasRootAccess()
        _hasRoot.value = hasRootAccess

        if (hasRootAccess) {
            Log.d(TAG, "ROOT ACCESS GRANTED - Full protection enabled")
            
            // Clara dizinlerini oluştur
            createClaraDirectories()

            // Daemon kontrolü
            val daemonRunning = RootExecutor.isProcessRunning("clara_orchestrator")

            if (daemonRunning) {
                // Daemon çalışıyor - IPC bağlantısı kur
                val ipcConnected = DaemonIpcClient.connect()
                if (ipcConnected) {
                    _connectionMode.value = ConnectionMode.FULL
                    _isConnected.value = true
                    Log.d(TAG, "Mode: FULL (Daemon + Root + IPC)")
                    
                    // Daemon'dan status al
                    val status = DaemonIpcClient.getStatus()
                    Log.d(TAG, "Daemon status: $status")
                } else {
                    _connectionMode.value = ConnectionMode.ROOT_ONLY
                    _isConnected.value = true
                    Log.w(TAG, "Mode: ROOT_ONLY (Daemon running but IPC failed)")
                }
            } else {
                _connectionMode.value = ConnectionMode.ROOT_ONLY
                _isConnected.value = true
                Log.d(TAG, "Mode: ROOT_ONLY")
            }
            
            // Daemon durumlarını kontrol et
            checkDaemonStatuses()
        } else {
            _connectionMode.value = ConnectionMode.NO_ROOT
            _isConnected.value = false
            Log.w(TAG, "Mode: NO_ROOT - Limited protection")
        }

        // Veritabanını yükle
        loadRecentThreats()
        loadStats()
        loadLockedApps()
        
        Log.d(TAG, "CLARA Security System initialized")
    }
    
    private suspend fun createClaraDirectories() = withContext(Dispatchers.IO) {
        if (_hasRoot.value) {
            RootExecutor.execute("mkdir -p /data/clara/logs")
            RootExecutor.execute("mkdir -p /data/clara/database")
            RootExecutor.execute("mkdir -p /data/clara/quarantine")
            RootExecutor.execute("mkdir -p /data/clara/blocklists")
            RootExecutor.execute("mkdir -p /data/clara/signatures")
            RootExecutor.execute("chmod -R 755 /data/clara")
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DAEMON MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    suspend fun checkDaemonStatuses() = withContext(Dispatchers.IO) {
        val daemons = listOf(
            "clara_orchestrator" to "Orchestrator",
            "clara_security_core" to "Security Core",
            "clara_privacy_core" to "Privacy Core",
            "clara_app_manager" to "App Manager"
        )

        val statuses = daemons.map { (process, name) ->
            val pid = RootExecutor.getProcessPid(process)
            DaemonStatus(
                name = name,
                isRunning = pid > 0,
                pid = pid
            )
        }

        _daemonStatuses.value = statuses
    }

    suspend fun startDaemon(daemonName: String): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        
        val processName = when (daemonName.lowercase()) {
            "orchestrator" -> "clara_orchestrator"
            "security", "security_core" -> "clara_security_core"
            "privacy", "privacy_core" -> "clara_privacy_core"
            "app", "app_manager" -> "clara_app_manager"
            else -> daemonName
        }
        
        Log.d(TAG, "Starting daemon: $processName")
        val result = RootExecutor.execute("/system/bin/$processName &")
        kotlinx.coroutines.delay(500)
        checkDaemonStatuses()
        return@withContext result.isSuccess
    }

    suspend fun stopDaemon(daemonName: String): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        
        val processName = when (daemonName.lowercase()) {
            "orchestrator" -> "clara_orchestrator"
            "security", "security_core" -> "clara_security_core"
            "privacy", "privacy_core" -> "clara_privacy_core"
            "app", "app_manager" -> "clara_app_manager"
            else -> daemonName
        }
        
        Log.d(TAG, "Stopping daemon: $processName")
        val result = RootExecutor.execute("pkill -9 $processName")
        kotlinx.coroutines.delay(300)
        checkDaemonStatuses()
        return@withContext result.isSuccess
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // FULL SYSTEM SCAN - GERÇEK TARAMA
    // ═══════════════════════════════════════════════════════════════════════════
    
    suspend fun startScan(): Boolean = withContext(Dispatchers.IO) {
        if (_isScanning.value) return@withContext false
        
        _isScanning.value = true
        _scanProgress.value = 0
        
        Log.d(TAG, "═══════════════════════════════════════════")
        Log.d(TAG, "CLARA SECURITY - FULL SYSTEM SCAN STARTED")
        Log.d(TAG, "═══════════════════════════════════════════")
        
        var totalThreats = 0
        
        try {
            // 1. UYGULAMA TARAMASI (%0-30)
            Log.d(TAG, "[1/5] Scanning installed applications...")
            totalThreats += scanInstalledApps()
            _scanProgress.value = 30
            
            // 2. DOSYA SİSTEMİ TARAMASI (%30-60)
            Log.d(TAG, "[2/5] Scanning file system...")
            if (_hasRoot.value) {
                totalThreats += scanFileSystemWithRoot()
            } else {
                totalThreats += scanFileSystemNoRoot()
            }
            _scanProgress.value = 60
            
            // 3. AĞ BAĞLANTILARI KONTROLÜ (%60-75)
            Log.d(TAG, "[3/5] Checking network connections...")
            if (_hasRoot.value) {
                totalThreats += scanNetworkConnections()
            }
            _scanProgress.value = 75
            
            // 4. SİSTEM KONTROLÜ (%75-90)
            Log.d(TAG, "[4/5] Checking system integrity...")
            if (_hasRoot.value) {
                totalThreats += checkSystemIntegrity()
            }
            _scanProgress.value = 90
            
            // 5. FİNAL (%90-100)
            Log.d(TAG, "[5/5] Finalizing scan results...")
            checkDaemonStatuses()
            loadRecentThreats()
            loadStats()
            _scanProgress.value = 100
            
            Log.d(TAG, "═══════════════════════════════════════════")
            Log.d(TAG, "SCAN COMPLETE - Found $totalThreats threats")
            Log.d(TAG, "═══════════════════════════════════════════")
            
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Scan failed", e)
            return@withContext false
        } finally {
            _isScanning.value = false
        }
    }
    
    /**
     * Yüklü uygulamaları tara - tehlikeli izinler, bilinen zararlılar
     */
    private suspend fun scanInstalledApps(): Int = withContext(Dispatchers.IO) {
        var threats = 0
        val pm = _context.packageManager
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        
        for (pkg in packages) {
            // Sistem uygulamalarını atla (opsiyonel)
            val isSystem = (pkg.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM != 0
            
            // 1. Bilinen zararlı paket kontrolü
            if (KNOWN_MALWARE_PACKAGES.any { pkg.packageName.contains(it, ignoreCase = true) }) {
                ThreatDatabase.saveThreat(
                    context = _context,
                    type = "MALWARE_APP",
                    source = "AppScanner",
                    description = "Bilinen zararlı uygulama tespit edildi: ${pkg.packageName}",
                    severity = 9
                )
                threats++
                Log.w(TAG, "THREAT: Known malware package - ${pkg.packageName}")
            }
            
            // 2. Tehlikeli izin kombinasyonu kontrolü
            val permissions = pkg.requestedPermissions ?: emptyArray()
            val dangerousCount = permissions.count { perm -> 
                DANGEROUS_PERMISSIONS.any { it == perm }
            }
            
            if (!isSystem && dangerousCount >= 5) {
                ThreatDatabase.saveThreat(
                    context = _context,
                    type = "SUSPICIOUS_APP",
                    source = "AppScanner",
                    description = "Şüpheli uygulama: ${pkg.packageName} ($dangerousCount tehlikeli izin)",
                    severity = 5
                )
                threats++
                Log.w(TAG, "SUSPICIOUS: ${pkg.packageName} has $dangerousCount dangerous permissions")
            }
            
            // 3. Accessibility + SMS kombinasyonu (yüksek risk)
            val hasAccessibility = permissions.any { it.contains("ACCESSIBILITY") }
            val hasSms = permissions.any { it.contains("SMS") }
            if (!isSystem && hasAccessibility && hasSms) {
                ThreatDatabase.saveThreat(
                    context = _context,
                    type = "SPYWARE_SUSPECT",
                    source = "AppScanner",
                    description = "Casus yazılım şüphelisi: ${pkg.packageName} (Accessibility + SMS)",
                    severity = 8
                )
                threats++
                Log.w(TAG, "SPYWARE SUSPECT: ${pkg.packageName}")
            }
        }
        
        return@withContext threats
    }
    
    /**
     * Dosya sistemi taraması - Root ile tam erişim
     */
    private suspend fun scanFileSystemWithRoot(): Int = withContext(Dispatchers.IO) {
        var threats = 0
        
        for (dir in SCAN_DIRECTORIES) {
            // Root ile dizin listesi al
            val result = RootExecutor.execute("find $dir -type f 2>/dev/null | head -500")
            if (result.isFailure) continue
            
            val files = result.getOrDefault("").lines().filter { it.isNotBlank() }
            
            for (filePath in files) {
                val file = File(filePath)
                val extension = file.extension.lowercase()
                
                // 1. Tehlikeli uzantı kontrolü
                if (extension in DANGEROUS_EXTENSIONS) {
                    // APK dosyalarını özel kontrol et
                    if (extension == "apk") {
                        val sha256 = calculateFileSha256WithRoot(filePath)
                        if (sha256 in KNOWN_MALWARE_HASHES) {
                            ThreatDatabase.saveThreat(
                                context = _context,
                                type = "MALWARE_FILE",
                                source = "FileScanner",
                                description = "Bilinen zararlı dosya: ${file.name}",
                                severity = 10
                            )
                            threats++
                            
                            // Otomatik karantinaya al
                            quarantineFile(filePath)
                            Log.w(TAG, "MALWARE FILE quarantined: $filePath")
                        }
                    }
                    
                    // /data/local/tmp içinde executable
                    if (filePath.contains("/data/local/tmp") && extension in listOf("sh", "so", "dex")) {
                        ThreatDatabase.saveThreat(
                            context = _context,
                            type = "SUSPICIOUS_EXECUTABLE",
                            source = "FileScanner",
                            description = "Şüpheli çalıştırılabilir: ${file.name}",
                            severity = 7
                        )
                        threats++
                        Log.w(TAG, "SUSPICIOUS: Executable in tmp - $filePath")
                    }
                }
            }
        }
        
        return@withContext threats
    }
    
    /**
     * Dosya sistemi taraması - Root yok
     */
    private suspend fun scanFileSystemNoRoot(): Int = withContext(Dispatchers.IO) {
        var threats = 0
        
        val downloadDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        
        if (downloadDir.exists() && downloadDir.canRead()) {
            downloadDir.walkTopDown().forEach { file ->
                if (file.isFile && file.extension.lowercase() == "apk") {
                    // APK bulundu - uyar
                    ThreatDatabase.saveThreat(
                        context = _context,
                        type = "UNKNOWN_APK",
                        source = "FileScanner",
                        description = "İndirilmiş APK: ${file.name}",
                        severity = 3
                    )
                    threats++
                }
            }
        }
        
        return@withContext threats
    }
    
    /**
     * Ağ bağlantılarını kontrol et
     */
    private suspend fun scanNetworkConnections(): Int = withContext(Dispatchers.IO) {
        var threats = 0
        
        // Aktif ağ bağlantılarını kontrol et
        val netstat = RootExecutor.execute("netstat -tunp 2>/dev/null | grep ESTABLISHED")
        if (netstat.isSuccess) {
            val connections = netstat.getOrDefault("").lines()
            
            // Bilinen zararlı IP'ler veya portlar
            val suspiciousPorts = listOf(4444, 5555, 6666, 7777, 1337, 31337)
            
            connections.forEach { line ->
                suspiciousPorts.forEach { port ->
                    if (line.contains(":$port ")) {
                        ThreatDatabase.saveThreat(
                            context = _context,
                            type = "SUSPICIOUS_CONNECTION",
                            source = "NetworkScanner",
                            description = "Şüpheli bağlantı port $port: $line",
                            severity = 8
                        )
                        threats++
                        Log.w(TAG, "SUSPICIOUS CONNECTION: Port $port")
                    }
                }
            }
        }
        
        return@withContext threats
    }
    
    /**
     * Sistem bütünlüğü kontrolü
     */
    private suspend fun checkSystemIntegrity(): Int = withContext(Dispatchers.IO) {
        var threats = 0
        
        // 1. SELinux durumu
        val selinux = RootExecutor.execute("getenforce")
        if (selinux.getOrDefault("").trim().lowercase() == "permissive") {
            ThreatDatabase.saveThreat(
                context = _context,
                type = "SYSTEM_RISK",
                source = "SystemCheck",
                description = "SELinux Permissive modunda - güvenlik riski",
                severity = 6
            )
            threats++
        }
        
        // 2. /system/app ve /system/priv-app değişiklik kontrolü
        val systemApps = RootExecutor.execute("ls -la /system/app 2>/dev/null | wc -l")
        Log.d(TAG, "System apps count: ${systemApps.getOrDefault("0")}")
        
        // 3. Magisk/KernelSU modül sayısı (bilgi)
        val modules = RootExecutor.execute("ls /data/adb/modules 2>/dev/null | wc -l")
        Log.d(TAG, "Installed modules: ${modules.getOrDefault("0")}")
        
        return@withContext threats
    }
    
    /**
     * Dosya SHA256 hesapla (root ile)
     */
    private suspend fun calculateFileSha256WithRoot(path: String): String = withContext(Dispatchers.IO) {
        val result = RootExecutor.execute("sha256sum '$path' 2>/dev/null | cut -d' ' -f1")
        return@withContext result.getOrDefault("").trim()
    }
    
    /**
     * Dosyayı karantinaya al
     */
    private suspend fun quarantineFile(path: String): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        
        val fileName = File(path).name
        val quarantinePath = "/data/clara/quarantine/${System.currentTimeMillis()}_$fileName"
        
        val result = RootExecutor.execute("mv '$path' '$quarantinePath' && chmod 000 '$quarantinePath'")
        Log.d(TAG, "Quarantined: $path -> $quarantinePath")
        
        return@withContext result.isSuccess
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BLOCKLIST MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════
    
    suspend fun updateBlocklists(): Boolean = withContext(Dispatchers.IO) {
        Log.d(TAG, "Updating blocklists...")
        
        try {
            // Tracker ve reklam domain listesi
            val trackerDomains = """
                # Trackers
                facebook.com/tr
                connect.facebook.net
                graph.facebook.com
                pixel.facebook.com
                # Analytics
                google-analytics.com
                analytics.google.com
                googletagmanager.com
                googleadservices.com
                doubleclick.net
                # Ad Networks
                googlesyndication.com
                pagead2.googlesyndication.com
                adservice.google.com
                # Mobile Trackers
                crashlytics.com
                firebase.google.com
                appsflyer.com
                adjust.com
                branch.io
                amplitude.com
                mixpanel.com
                segment.io
                # Chinese Trackers
                umeng.com
                cnzz.com
                baidu.com/tracking
                # Russian Trackers
                mc.yandex.ru
                # Social
                ads.twitter.com
                analytics.twitter.com
                ads-api.twitter.com
            """.trimIndent()
            
            // Yerel dosyaya yaz
            val blocklistDir = File(_context.filesDir, "blocklists")
            blocklistDir.mkdirs()
            File(blocklistDir, "trackers.txt").writeText(trackerDomains)
            
            // Root varsa sistem dizinine de yaz
            if (_hasRoot.value) {
                RootExecutor.execute("echo '$trackerDomains' > /data/clara/blocklists/trackers.txt")
                RootExecutor.execute("chmod 644 /data/clara/blocklists/trackers.txt")
                
                // Daemon'a bildir
                RootExecutor.execute("echo 'reload:blocklist' > /data/clara/commands")
            }
            
            Log.d(TAG, "Blocklist updated successfully")
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Blocklist update failed", e)
            return@withContext false
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QUARANTINE MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════
    
    suspend fun clearQuarantine(): Boolean = withContext(Dispatchers.IO) {
        Log.d(TAG, "Clearing quarantine...")
        
        try {
            // Yerel karantina
            val localQuarantine = File(_context.filesDir, "quarantine")
            if (localQuarantine.exists()) {
                localQuarantine.listFiles()?.forEach { it.deleteRecursively() }
            }
            
            // Root karantina
            if (_hasRoot.value) {
                RootExecutor.execute("rm -rf /data/clara/quarantine/*")
            }
            
            loadStats()
            Log.d(TAG, "Quarantine cleared")
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Clear quarantine failed", e)
            return@withContext false
        }
    }
    
    suspend fun getQuarantinedFiles(): List<String> = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext emptyList()
        
        val result = RootExecutor.execute("ls /data/clara/quarantine 2>/dev/null")
        return@withContext result.getOrDefault("").lines().filter { it.isNotBlank() }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // THREAT MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    suspend fun loadRecentThreats(limit: Int = 50) = withContext(Dispatchers.IO) {
        try {
            val threats = ThreatDatabase.loadThreats(_context)
            _recentThreats.value = threats.take(limit).map { threat ->
                ThreatInfo(
                    id = threat.id,
                    type = ThreatType.fromString(threat.type),
                    level = ThreatLevel.fromSeverity(threat.severity),
                    source = threat.source,
                    description = threat.description,
                    timestamp = threat.timestamp,
                    isHandled = threat.resolved
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load threats", e)
        }
    }

    suspend fun loadStats() = withContext(Dispatchers.IO) {
        try {
            val threats = ThreatDatabase.loadThreats(_context)
            val today = System.currentTimeMillis() - (24 * 60 * 60 * 1000)
            
            _stats.value = SecurityStats(
                totalThreats = threats.size,
                threatsToday = threats.count { it.timestamp > today },
                trackersBlocked = threats.count { it.type.contains("TRACKER", ignoreCase = true) },
                smsScanned = threats.count { it.source == "SmsScanner" },
                filesScanned = threats.count { it.source == "FileScanner" }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load stats", e)
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // APP LOCK
    // ═══════════════════════════════════════════════════════════════════════════

    suspend fun loadLockedApps() = withContext(Dispatchers.IO) {
        try {
            val prefs = _context.getSharedPreferences("clara_app_lock", Context.MODE_PRIVATE)
            val json = prefs.getString(LOCKED_APPS_PREF_KEY, "[]")
            val type = object : TypeToken<List<LockedApp>>() {}.type
            _lockedApps.value = Gson().fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load locked apps", e)
        }
    }

    suspend fun addLockedApp(packageName: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val pm = _context.packageManager
            val appInfo = pm.getApplicationInfo(packageName, 0)
            val appName = pm.getApplicationLabel(appInfo).toString()
            
            val newApp = LockedApp(packageName = packageName, appName = appName)
            val updated = _lockedApps.value + newApp
            
            saveLockedApps(updated)
            _lockedApps.value = updated
            return@withContext true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add locked app", e)
            return@withContext false
        }
    }

    suspend fun removeLockedApp(packageName: String): Boolean = withContext(Dispatchers.IO) {
        val updated = _lockedApps.value.filter { it.packageName != packageName }
        saveLockedApps(updated)
        _lockedApps.value = updated
        return@withContext true
    }

    private fun saveLockedApps(apps: List<LockedApp>) {
        val prefs = _context.getSharedPreferences("clara_app_lock", Context.MODE_PRIVATE)
        prefs.edit().putString(LOCKED_APPS_PREF_KEY, Gson().toJson(apps)).apply()
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // HELPER METHODS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Tüm verileri yükle
     */
    suspend fun loadAllData() = withContext(Dispatchers.IO) {
        checkDaemonStatuses()
        loadRecentThreats()
        loadStats()
        loadLockedApps()
        loadInstalledApps()
    }
    
    /**
     * Yüklü uygulamaları al
     */
    suspend fun loadInstalledApps() = withContext(Dispatchers.IO) {
        try {
            val pm = _context.packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            
            _installedApps.value = packages
                .filter { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
                .map { appInfo ->
                    AppInfo(
                        packageName = appInfo.packageName,
                        appName = pm.getApplicationLabel(appInfo).toString()
                    )
                }
                .sortedBy { it.appName.lowercase() }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load installed apps", e)
        }
    }
    
    /**
     * Uygulama kilidi ayarla
     */
    suspend fun setAppLocked(packageName: String, locked: Boolean): Boolean = withContext(Dispatchers.IO) {
        return@withContext if (locked) {
            addLockedApp(packageName)
        } else {
            removeLockedApp(packageName)
        }
    }
}
