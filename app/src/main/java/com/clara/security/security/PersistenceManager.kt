package com.clara.security.security

import android.content.Context
import android.util.Log
import com.clara.security.data.RootExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * CLARA Süreklilik Yöneticisi
 * 
 * Sistemin her zaman ayakta kalmasını sağlar.
 * KernelSU/Magisk service.d scriptleri ile watchdog oluşturur.
 */
object PersistenceManager {
    private const val TAG = "PersistenceManager"
    private const val WATCHDOG_SCRIPT_PATH = "/data/adb/service.d/clara_watchdog.sh"

    /**
     * Watchdog scriptini sisteme enjekte et
     */
    suspend fun installUnkillableWatchdog(context: Context) = withContext(Dispatchers.IO) {
        if (!RootExecutor.hasRootAccess()) {
            Log.e(TAG, "Root required for persistence!")
            return@withContext
        }
        
        Log.d(TAG, "Installing unkillable watchdog...")
        
        // Watchdog scripti içeriği
        // Bu script sonsuz döngüde çalışır ve CLARA servisinin çalışıp çalışmadığını kontrol eder.
        // Eğer servis düşerse, tekrar başlatır.
        val scriptContent = """
            #!/system/bin/sh
            
            # CLARA Security Watchdog
            # Bu script KernelSU/Magisk tarafından boot sırasında çalıştırılır.
            
            PKG="com.clara.security"
            CLS="com.clara.security.service.RealTimeProtectionService"
            LOG_FILE="/data/clara/watchdog.log"
            
            echo "[\$(date)] CLARA Watchdog Started" >> \$LOG_FILE
            
            # Bekle sistem tam açılsın
            sleep 60
            
            while true; do
                # Servis çalışıyor mu kontrol et
                if ! pgrep -f "com.clara.security" > /dev/null; then
                    echo "[\$(date)] Service DIED, restarting..." >> \$LOG_FILE
                    
                    # Uygulamayı başlat
                    am start-foreground-service -n \$PKG/\$CLS
                    
                    # Eğer foreground service başlatılamazsa, main activity'i başlat
                    sleep 5
                    if ! pgrep -f "com.clara.security" > /dev/null; then
                         am start -n \$PKG/.MainActivity
                    fi
                fi
                
                # USB Debugging güvenliği (İsteğe bağlı - Strict Mode)
                # settings get global adb_enabled
                
                sleep 20
            done
        """.trimIndent()
        
        // Scripti diske yaz
        val tempFile = java.io.File(context.cacheDir, "clara_watchdog.sh")
        tempFile.writeText(scriptContent)
        
        // Root ile sistem konumuna taşı ve yetki ver
        val cmds = listOf(
            "mkdir -p /data/adb/service.d",
            "cp ${tempFile.absolutePath} $WATCHDOG_SCRIPT_PATH",
            "chmod 755 $WATCHDOG_SCRIPT_PATH",
            "chown 0:0 $WATCHDOG_SCRIPT_PATH"
        )
        
        var success = true
        for (cmd in cmds) {
            val result = RootExecutor.execute(cmd)
            if (!result.isSuccess) success = false
        }
        
        if (success) {
            Log.d(TAG, "Watchdog installed successfully at $WATCHDOG_SCRIPT_PATH")
        } else {
            Log.e(TAG, "Failed to install watchdog")
        }
        
        tempFile.delete()
    }
    
    /**
     * Watchdog'u kaldır
     */
    suspend fun uninstallWatchdog() = withContext(Dispatchers.IO) {
        if (RootExecutor.hasRootAccess()) {
            RootExecutor.execute("rm $WATCHDOG_SCRIPT_PATH")
            Log.d(TAG, "Watchdog uninstalled")
        }
    }
}
