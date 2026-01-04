package com.clara.security.security

import android.content.Context
import android.util.Log
import com.clara.security.data.RootExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * CLARA Firewall Yöneticisi (Otonom Ağ Kalkanı)
 *
 * Linux çekirdeği seviyesinde (iptables) ağ trafiğini yönetir.
 * Root yetkisi ile çalışır ve tehditleri fiziksel olarak engeller.
 */
object FirewallManager {
    private const val TAG = "FirewallManager"
    private const val PREFS_NAME = "clara_firewall"

    // Chain isimleri
    private const val CHAIN_OUTPUT = "clara_output"
    private const val CHAIN_INPUT = "clara_input"

    // Firewall Durumu
    var isEnabled: Boolean = false
        private set

    /**
     * Firewall sistemini başlat ve kuralları uygula
     */
    suspend fun initialize(context: Context) = withContext(Dispatchers.IO) {
        if (!RootExecutor.hasRootAccess()) {
            Log.e(TAG, "Root access required for Firewall!")
            return@withContext
        }

        Log.d(TAG, "Initializing Firewall chains...")
        
        // Temel chain'leri temizle ve oluştur (Idempotent)
        setupBaseChains()
        
        // Kayıtlı kuralları geri yükle
        restoreRules(context)
        
        isEnabled = true
        Log.d(TAG, "Firewall initialized and active.")
    }

    /**
     * Temel iptables zincirlerini oluştur
     */
    private suspend fun setupBaseChains() {
        // Eski zincirleri temizle
        RootExecutor.execute("iptables -D OUTPUT -j $CHAIN_OUTPUT 2>/dev/null")
        RootExecutor.execute("iptables -F $CHAIN_OUTPUT 2>/dev/null")
        RootExecutor.execute("iptables -X $CHAIN_OUTPUT 2>/dev/null")

        // Yeni zincir oluştur
        RootExecutor.execute("iptables -N $CHAIN_OUTPUT")
        
        // Ana OUTPUT zincirine bağla (Tüm giden trafik buradan geçecek)
        RootExecutor.execute("iptables -I OUTPUT 1 -j $CHAIN_OUTPUT")
        
        // Varsayılan politika: Kabul et (Engelleme listesi mantığı)
        // Eğer "Strict Mode" açılırsa, buranın sonuna DROP eklenir.
    }

    /**
     * Bir uygulamanın internet erişimini ENGELLE (UID bazlı)
     */
    suspend fun blockApp(uid: Int): Boolean = withContext(Dispatchers.IO) {
        if (!isEnabled) {
            Log.w(TAG, "Firewall not enabled, cannot block app.")
            return@withContext false
        }

        // Kural: Bu UID'den gelen paketleri DROP et
        val cmd = "iptables -A $CHAIN_OUTPUT -m owner --uid-owner $uid -j DROP"
        val result = RootExecutor.execute(cmd)
        
        if (result.isSuccess) {
            Log.i(TAG, "BLOCKED traffic for UID: $uid")
            return@withContext true
        }
        return@withContext false
    }

    /**
     * Bir uygulamanın engelini KALDIR
     */
    suspend fun unblockApp(uid: Int): Boolean = withContext(Dispatchers.IO) {
        // Tam eşleşen kuralı sil
        val cmd = "iptables -D $CHAIN_OUTPUT -m owner --uid-owner $uid -j DROP"
        val result = RootExecutor.execute(cmd)
        
        if (result.isSuccess) {
            Log.i(TAG, "UNBLOCKED traffic for UID: $uid")
            return@withContext true
        }
        return@withContext false
    }

    /**
     * Belirli bir IP adresine erişimi ENGELLE (Sunucu bazlı)
     */
    suspend fun blockIp(ipAddress: String): Boolean = withContext(Dispatchers.IO) {
        // Giden (OUTPUT) trafiği engelle
        val cmdOut = "iptables -A $CHAIN_OUTPUT -d $ipAddress -j DROP"
        val resOut = RootExecutor.execute(cmdOut)
        
        // Gelen (INPUT) trafiği de engelle (isteğe bağlı ama güvenli)
        // INPUT zinciri yönetimi biraz daha karmaşık olabilir, şimdilik sadece OUTPUT.
        
        if (resOut.isSuccess) {
            Log.i(TAG, "BLOCKED connection to IP: $ipAddress")
            return@withContext true
        }
        return@withContext false
    }

    /**
     * Acil Durum: Tüm interneti kes (Kill Switch)
     */
    suspend fun enableKillSwitch() = withContext(Dispatchers.IO) {
        // En başa DROP kuralı ekle
        RootExecutor.execute("iptables -I $CHAIN_OUTPUT 1 -j DROP")
        Log.w(TAG, "KILL SWITCH ENABLED - All network traffic blocked!")
    }

    /**
     * Acil Durum: İnterneti geri getir
     */
    suspend fun disableKillSwitch() = withContext(Dispatchers.IO) {
        RootExecutor.execute("iptables -D $CHAIN_OUTPUT -j DROP 2>/dev/null")
        Log.w(TAG, "Kill switch disabled.")
    }

    /**
     * Kuralları JSON/Prefs'den geri yükle
     */
    private suspend fun restoreRules(context: Context) {
        // TODO: SharedPreferences'dan engelli UID listesini çek ve döngüyle blockApp çağır.
        // Şimdilik örnek:
        // val blockedUids = prefs.getStringSet("blocked_uids", emptySet())
        // blockedUids.forEach { blockApp(it.toInt()) }
    }

    /**
     * Firewall'ı tamamen kapat (Zincirleri temizle)
     */
    suspend fun shutdown() = withContext(Dispatchers.IO) {
        RootExecutor.execute("iptables -D OUTPUT -j $CHAIN_OUTPUT 2>/dev/null")
        RootExecutor.execute("iptables -F $CHAIN_OUTPUT 2>/dev/null")
        RootExecutor.execute("iptables -X $CHAIN_OUTPUT 2>/dev/null")
        isEnabled = false
        Log.d(TAG, "Firewall shutdown complete.")
    }
}
