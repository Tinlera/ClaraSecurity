package com.clara.security.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Security Preferences
 *
 * Tüm güvenlik ayarları burada yönetilir.
 * DEFAULT: TÜM ÖZELLİKLER AÇIK
 */
object SecurityPreferences {
    private const val TAG = "SecurityPreferences"
    private const val PREFS_NAME = "clara_security_prefs_encrypted"

    private var prefs: SharedPreferences? = null

    // ═══════════════════════════════════════════════════════════════════════════
    // SETTINGS KEYS
    // ═══════════════════════════════════════════════════════════════════════════

    private const val KEY_ANTI_THEFT_ENABLED = "anti_theft_enabled"
    private const val KEY_OVERLAY_LOCK_ENABLED = "overlay_lock_enabled"
    private const val KEY_AI_AUTO_ACTION_ENABLED = "ai_auto_action_enabled"
    private const val KEY_VOICE_PRINT_ENABLED = "voice_print_enabled"
    private const val KEY_SMS_SCAN_ENABLED = "sms_scan_enabled"
    private const val KEY_FILE_SCAN_ENABLED = "file_scan_enabled"
    private const val KEY_NETWORK_MONITOR_ENABLED = "network_monitor_enabled"
    private const val KEY_TRACKER_BLOCK_ENABLED = "tracker_block_enabled"
    private const val KEY_APP_LOCK_ENABLED = "app_lock_enabled"
    private const val KEY_ROOT_HIDER_ENABLED = "root_hider_enabled"
    private const val KEY_APP_LOCK_PIN = "app_lock_pin"
    private const val KEY_SHAKE_SENSITIVITY = "shake_sensitivity"
    private const val KEY_FIRST_RUN = "first_run"

    // ═══════════════════════════════════════════════════════════════════════════
    // STATE FLOWS
    // ═══════════════════════════════════════════════════════════════════════════

    private val _antiTheftEnabled = MutableStateFlow(false)  // VARSAYILAN KAPALI
    val antiTheftEnabled: StateFlow<Boolean> = _antiTheftEnabled.asStateFlow()

    private val _overlayLockEnabled = MutableStateFlow(true)
    val overlayLockEnabled: StateFlow<Boolean> = _overlayLockEnabled.asStateFlow()

    private val _aiAutoActionEnabled = MutableStateFlow(true)
    val aiAutoActionEnabled: StateFlow<Boolean> = _aiAutoActionEnabled.asStateFlow()

    private val _voicePrintEnabled = MutableStateFlow(true)
    val voicePrintEnabled: StateFlow<Boolean> = _voicePrintEnabled.asStateFlow()

    private val _smsScanEnabled = MutableStateFlow(true)
    val smsScanEnabled: StateFlow<Boolean> = _smsScanEnabled.asStateFlow()

    private val _fileScanEnabled = MutableStateFlow(true)
    val fileScanEnabled: StateFlow<Boolean> = _fileScanEnabled.asStateFlow()

    private val _networkMonitorEnabled = MutableStateFlow(true)
    val networkMonitorEnabled: StateFlow<Boolean> = _networkMonitorEnabled.asStateFlow()

    private val _trackerBlockEnabled = MutableStateFlow(true)
    val trackerBlockEnabled: StateFlow<Boolean> = _trackerBlockEnabled.asStateFlow()
    
    private val _appLockEnabled = MutableStateFlow(false)
    val appLockEnabled: StateFlow<Boolean> = _appLockEnabled.asStateFlow()

    private val _rootHiderEnabled = MutableStateFlow(true)
    val rootHiderEnabled: StateFlow<Boolean> = _rootHiderEnabled.asStateFlow()

    /**
     * Initialize
     */
    fun initialize(context: Context) {
        try {
            val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
            prefs = EncryptedSharedPreferences.create(
                PREFS_NAME,
                masterKeyAlias,
                context,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create EncryptedSharedPreferences, falling back to regular SharedPreferences", e)
            prefs = context.getSharedPreferences("clara_security_prefs", Context.MODE_PRIVATE)
        }

        val isFirstRun = prefs?.getBoolean(KEY_FIRST_RUN, true) ?: true

        if (isFirstRun) {
            setDefaults()
            prefs?.edit()?.putBoolean(KEY_FIRST_RUN, false)?.apply()
            Log.d(TAG, "First run - all settings set to DEFAULT")
        } else {
            loadSettings()
        }
    }

    private fun setDefaults() {
        prefs?.edit()?.apply {
            putBoolean(KEY_ANTI_THEFT_ENABLED, false)  // VARSAYILAN KAPALI
            putBoolean(KEY_OVERLAY_LOCK_ENABLED, true)
            putBoolean(KEY_AI_AUTO_ACTION_ENABLED, true)
            putBoolean(KEY_VOICE_PRINT_ENABLED, true)
            putBoolean(KEY_SMS_SCAN_ENABLED, true)
            putBoolean(KEY_FILE_SCAN_ENABLED, true)
            putBoolean(KEY_NETWORK_MONITOR_ENABLED, true)
            putBoolean(KEY_TRACKER_BLOCK_ENABLED, true)
            putBoolean(KEY_APP_LOCK_ENABLED, false)
            putBoolean(KEY_ROOT_HIDER_ENABLED, true)
            putFloat(KEY_SHAKE_SENSITIVITY, 100f)
            apply()
        }
        loadSettings() 
    }

    private fun loadSettings() {
        prefs?.let { p ->
            _antiTheftEnabled.value = p.getBoolean(KEY_ANTI_THEFT_ENABLED, true)
            _overlayLockEnabled.value = p.getBoolean(KEY_OVERLAY_LOCK_ENABLED, true)
            _aiAutoActionEnabled.value = p.getBoolean(KEY_AI_AUTO_ACTION_ENABLED, true)
            _voicePrintEnabled.value = p.getBoolean(KEY_VOICE_PRINT_ENABLED, true)
            _smsScanEnabled.value = p.getBoolean(KEY_SMS_SCAN_ENABLED, true)
            _fileScanEnabled.value = p.getBoolean(KEY_FILE_SCAN_ENABLED, true)
            _networkMonitorEnabled.value = p.getBoolean(KEY_NETWORK_MONITOR_ENABLED, true)
            _trackerBlockEnabled.value = p.getBoolean(KEY_TRACKER_BLOCK_ENABLED, true)
            _appLockEnabled.value = p.getBoolean(KEY_APP_LOCK_ENABLED, false)
            _rootHiderEnabled.value = p.getBoolean(KEY_ROOT_HIDER_ENABLED, true)
        }
        Log.d(TAG, "Settings loaded.")
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // SETTERS
    // ═══════════════════════════════════════════════════════════════════════════

    fun setAppLockPin(pin: String) {
        prefs?.edit()?.putString(KEY_APP_LOCK_PIN, pin)?.apply()
    }

    fun getAppLockPin(): String? {
        return prefs?.getString(KEY_APP_LOCK_PIN, null)
    }

    fun setAntiTheftEnabled(enabled: Boolean) {
        _antiTheftEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_ANTI_THEFT_ENABLED, enabled)?.apply()

        if (enabled) {
            AntiTheftManager.startProtection()
        } else {
            AntiTheftManager.stopProtection()
        }
    }
    
    // ... (other setters)
    fun setSmsScanEnabled(enabled: Boolean) {
        _smsScanEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_SMS_SCAN_ENABLED, enabled)?.apply()
    }
    
    fun setFileScanEnabled(enabled: Boolean) {
        _fileScanEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_FILE_SCAN_ENABLED, enabled)?.apply()
    }

    fun setNetworkMonitorEnabled(enabled: Boolean) {
        _networkMonitorEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_NETWORK_MONITOR_ENABLED, enabled)?.apply()
    }

    fun setTrackerBlockEnabled(enabled: Boolean) {
        _trackerBlockEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_TRACKER_BLOCK_ENABLED, enabled)?.apply()
    }
    
    fun setAppLockEnabled(enabled: Boolean) {
        _appLockEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_APP_LOCK_ENABLED, enabled)?.apply()
    }
    
    fun setRootHiderEnabled(enabled: Boolean) {
        _rootHiderEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_ROOT_HIDER_ENABLED, enabled)?.apply()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // ADDITIONAL SETTERS
    // ═══════════════════════════════════════════════════════════════════════════

    fun setOverlayLockEnabled(enabled: Boolean) {
        _overlayLockEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_OVERLAY_LOCK_ENABLED, enabled)?.apply()
    }

    fun setAiAutoActionEnabled(enabled: Boolean) {
        _aiAutoActionEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_AI_AUTO_ACTION_ENABLED, enabled)?.apply()
    }

    fun setVoicePrintEnabled(enabled: Boolean) {
        _voicePrintEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_VOICE_PRINT_ENABLED, enabled)?.apply()
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // QUICK ACCESS
    // ═══════════════════════════════════════════════════════════════════════════

    fun isSmsScanEnabled() = _smsScanEnabled.value
    fun isFileScanEnabled() = _fileScanEnabled.value
    fun isNetworkMonitorEnabled() = _networkMonitorEnabled.value
    fun isTrackerBlockEnabled() = _trackerBlockEnabled.value
    fun isAppLockEnabled() = _appLockEnabled.value
    fun isRootHiderEnabled() = _rootHiderEnabled.value
    fun isAntiTheftEnabled() = _antiTheftEnabled.value
    fun isOverlayLockEnabled() = _overlayLockEnabled.value
    fun isAiAutoActionEnabled() = _aiAutoActionEnabled.value
    fun isVoicePrintEnabled() = _voicePrintEnabled.value
}
