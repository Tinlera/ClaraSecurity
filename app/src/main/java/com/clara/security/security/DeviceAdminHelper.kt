package com.clara.security.security

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import com.clara.security.receiver.ClaraDeviceAdminReceiver

/**
 * Device Admin Helper
 * 
 * Cihaz yönetici haklarını yönetir:
 * - Aktivasyon isteği
 * - Durum kontrolü
 * - Cihaz kilitleme
 * - Veri silme
 */
object DeviceAdminHelper {
    private const val TAG = "DeviceAdminHelper"
    const val REQUEST_CODE_ENABLE_ADMIN = 1001
    
    private var devicePolicyManager: DevicePolicyManager? = null
    private var adminComponent: ComponentName? = null
    
    fun initialize(context: Context) {
        devicePolicyManager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        adminComponent = ComponentName(context, ClaraDeviceAdminReceiver::class.java)
        Log.d(TAG, "DeviceAdminHelper initialized")
    }
    
    /**
     * Device Admin aktif mi?
     */
    fun isAdminActive(): Boolean {
        return adminComponent?.let { 
            devicePolicyManager?.isAdminActive(it) 
        } ?: false
    }
    
    /**
     * Device Admin aktivasyonu iste
     */
    fun requestAdminActivation(activity: Activity) {
        if (isAdminActive()) {
            Log.d(TAG, "Device Admin already active")
            return
        }
        
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent)
            putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "CLARA Security'nin anti-theft ve güvenlik özelliklerini kullanabilmesi için cihaz yöneticisi izni gereklidir.\n\n" +
                "Bu izinle:\n" +
                "• Cihazınızı uzaktan kilitleyebilir\n" +
                "• Yanlış şifre girişlerini izleyebilir\n" +
                "• Hırsızlık durumunda verileri silebilir"
            )
        }
        activity.startActivityForResult(intent, REQUEST_CODE_ENABLE_ADMIN)
        Log.d(TAG, "Device Admin activation requested")
    }
    
    /**
     * Cihazı kilitle
     */
    fun lockDevice() {
        if (isAdminActive()) {
            try {
                devicePolicyManager?.lockNow()
                Log.d(TAG, "Device locked successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to lock device", e)
            }
        } else {
            Log.w(TAG, "Cannot lock device - Admin not active")
        }
    }
    
    /**
     * Ekran kilit şifresini sıfırla (yeni şifre belirle)
     * NOT: Android 7.0+ sonrası kısıtlı
     */
    fun resetPassword(newPassword: String): Boolean {
        if (!isAdminActive()) {
            Log.w(TAG, "Cannot reset password - Admin not active")
            return false
        }
        
        return try {
            @Suppress("DEPRECATION")
            devicePolicyManager?.resetPassword(newPassword, 0)
            Log.d(TAG, "Password reset successfully")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to reset password", e)
            false
        }
    }
    
    /**
     * Tüm verileri sil (fabrika ayarları)
     * DİKKAT: Bu işlem geri alınamaz!
     */
    fun wipeData(reason: String = "CLARA Security - Uzaktan silme") {
        if (!isAdminActive()) {
            Log.w(TAG, "Cannot wipe data - Admin not active")
            return
        }
        
        try {
            Log.w(TAG, "WIPING DEVICE DATA - Reason: $reason")
            devicePolicyManager?.wipeData(0, reason)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to wipe data", e)
        }
    }
    
    /**
     * Kamerayı devre dışı bırak/etkinleştir
     */
    fun setCameraDisabled(disabled: Boolean): Boolean {
        if (!isAdminActive()) return false
        
        return try {
            adminComponent?.let {
                devicePolicyManager?.setCameraDisabled(it, disabled)
                Log.d(TAG, "Camera disabled: $disabled")
                true
            } ?: false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set camera state", e)
            false
        }
    }
    
    /**
     * Maksimum yanlış şifre denemesi ayarla
     * Bu sayıya ulaşılınca cihaz silinir
     */
    fun setMaxFailedPasswordAttempts(max: Int) {
        if (!isAdminActive()) return
        
        try {
            adminComponent?.let {
                devicePolicyManager?.setMaximumFailedPasswordsForWipe(it, max)
                Log.d(TAG, "Max failed password attempts set to: $max")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set max failed attempts", e)
        }
    }
    
    /**
     * Device Admin'i devre dışı bırak
     */
    fun removeAdmin() {
        if (isAdminActive()) {
            try {
                adminComponent?.let {
                    devicePolicyManager?.removeActiveAdmin(it)
                    Log.d(TAG, "Device Admin removed")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to remove admin", e)
            }
        }
    }
}
