package com.clara.security.receiver

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast

/**
 * CLARA Device Admin Receiver
 * 
 * Cihaz yönetici hakları ile güçlü güvenlik özellikleri sağlar:
 * - Cihazı kilitleme
 * - Ekran kilidini zorlama
 * - Veri silme (fabrika ayarları)
 * - Parola politikaları
 */
class ClaraDeviceAdminReceiver : DeviceAdminReceiver() {
    
    companion object {
        private const val TAG = "ClaraDeviceAdmin"
    }
    
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.d(TAG, "Device Admin enabled - CLARA Security now has full protection capabilities")
        Toast.makeText(context, "CLARA Cihaz Yöneticisi aktif!", Toast.LENGTH_SHORT).show()
    }
    
    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Log.w(TAG, "Device Admin disabled - Protection reduced")
        Toast.makeText(context, "CLARA Cihaz Yöneticisi devre dışı!", Toast.LENGTH_SHORT).show()
    }
    
    override fun onPasswordChanged(context: Context, intent: Intent, userHandle: android.os.UserHandle) {
        super.onPasswordChanged(context, intent, userHandle)
        Log.d(TAG, "Password changed")
    }
    
    override fun onPasswordFailed(context: Context, intent: Intent, userHandle: android.os.UserHandle) {
        super.onPasswordFailed(context, intent, userHandle)
        Log.w(TAG, "Password attempt failed!")
        // Anti-theft: Yanlış şifre girişi tespit edildi
        // Burada fotoğraf çekme, konum gönderme gibi işlemler yapılabilir
    }
    
    override fun onPasswordSucceeded(context: Context, intent: Intent, userHandle: android.os.UserHandle) {
        super.onPasswordSucceeded(context, intent, userHandle)
        Log.d(TAG, "Password succeeded")
    }
    
    override fun onLockTaskModeEntering(context: Context, intent: Intent, pkg: String) {
        super.onLockTaskModeEntering(context, intent, pkg)
        Log.d(TAG, "Lock task mode entering for: $pkg")
    }
    
    override fun onLockTaskModeExiting(context: Context, intent: Intent) {
        super.onLockTaskModeExiting(context, intent)
        Log.d(TAG, "Lock task mode exiting")
    }
}
