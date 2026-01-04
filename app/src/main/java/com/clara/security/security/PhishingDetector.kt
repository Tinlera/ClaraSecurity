package com.clara.security.security

import android.content.Context
import android.util.Log
import com.clara.security.data.ThreatDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.regex.Pattern

/**
 * Phishing Dedektörü
 * 
 * SMS ve URL'leri analiz ederek phishing tehditleri tespit eder.
 * Pattern matching + heuristic analiz kullanır.
 */
object PhishingDetector {
    private const val TAG = "PhishingDetector"
    
    // Phishing pattern'leri
    private val PHISHING_PATTERNS = listOf(
        // Banka/PTT dolandırıcılığı
        Pattern.compile("(hesab|kart|iban).*(bloke|dondur|iptal|güncelle)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(ptt|eft|havale).*(bekle|onay|doğrula)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(kredi|banka).*(limit|onay|şifre)", Pattern.CASE_INSENSITIVE),
        
        // Kargo dolandırıcılığı
        Pattern.compile("(kargo|paket|gönderi).*(bekle|teslimat|adres|güncelle)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(mng|aras|yurtiçi|ups|fedex).*(link|tıkla|gir)", Pattern.CASE_INSENSITIVE),
        
        // Hediye/Ödül dolandırıcılığı
        Pattern.compile("(kazan|ödül|hediye|çekiliş|talihli)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(tebrik|kutla).*(kazan|ödül)", Pattern.CASE_INSENSITIVE),
        
        // Acil eylem istekleri
        Pattern.compile("(acil|hemen|son|24 saat).*(tıkla|gir|ara|yap)", Pattern.CASE_INSENSITIVE),
        
        // Şüpheli URL pattern'leri
        Pattern.compile("https?://[a-z0-9-]+\\.(tk|ml|ga|cf|gq|xyz|top|work|click|link)/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bit\\.ly|tinyurl|t\\.co|goo\\.gl|is\\.gd|v\\.gd", Pattern.CASE_INSENSITIVE),
        
        // Sahte devlet/resmi kurum
        Pattern.compile("(sgk|vergi|e-devlet|nüfus).*(borç|ödeme|ceza)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(haciz|icra|mahkeme).*(son|acil)", Pattern.CASE_INSENSITIVE),
        
        // Kripto/Yatırım dolandırıcılığı
        Pattern.compile("(bitcoin|kripto|yatırım).*(kazan|getiri|%[0-9]+)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(günlük|aylık).*(gelir|kazanç).*(garanti|kesin)", Pattern.CASE_INSENSITIVE)
    )
    
    // Bilinen phishing domain'leri
    private val KNOWN_PHISHING_DOMAINS = listOf(
        "secure-update",
        "account-verify",
        "login-confirm",
        "bank-update",
        "ptt-kargo",
        "mng-kargo",
        "aras-kargo",
        "n11-odeme",
        "trendyol-odeme",
        "sahibinden-odeme"
    )
    
    // Güvenilir gönderenler (whitelist)
    private val TRUSTED_SENDERS = listOf(
        "TURKCELL", "VODAFONE", "TURK TELEKOM",
        "GARANTI", "AKBANK", "ISBANK", "YAPIKREDI", "ZIRAAT", "HALKBANK",
        "PTT", "MNG KARGO", "ARAS KARGO", "YURTICI"
    )
    
    data class AnalysisResult(
        val isPhishing: Boolean,
        val confidence: Float,
        val reason: String,
        val matchedPatterns: List<String>
    )
    
    /**
     * SMS mesajını analiz et
     */
    suspend fun analyzeSms(
        context: Context,
        sender: String,
        message: String
    ): AnalysisResult = withContext(Dispatchers.Default) {
        Log.d(TAG, "Analyzing SMS from $sender")
        
        val matchedPatterns = mutableListOf<String>()
        var riskScore = 0
        
        // 1. Pattern matching
        for (pattern in PHISHING_PATTERNS) {
            if (pattern.matcher(message).find()) {
                matchedPatterns.add(pattern.pattern())
                riskScore += 20
            }
        }
        
        // 2. URL analizi
        val urls = extractUrls(message)
        for (url in urls) {
            if (isPhishingUrl(url)) {
                matchedPatterns.add("Şüpheli URL: $url")
                riskScore += 40
            }
            
            // Kısaltılmış URL
            if (url.contains("bit.ly") || url.contains("tinyurl") || 
                url.contains("t.co") || url.contains("goo.gl")) {
                matchedPatterns.add("Kısaltılmış URL: $url")
                riskScore += 15
            }
        }
        
        // 3. Gönderen analizi
        val senderUpper = sender.uppercase()
        val isTrustedSender = TRUSTED_SENDERS.any { senderUpper.contains(it) }
        
        if (!isTrustedSender && urls.isNotEmpty()) {
            riskScore += 10 // Bilinmeyen gönderenden link
        }
        
        // 4. Heuristic analiz
        // Para/ödeme kelimeleri + URL
        if ((message.contains("TL", ignoreCase = true) || 
             message.contains("₺") || 
             message.contains("ödeme", ignoreCase = true)) && urls.isNotEmpty()) {
            riskScore += 25
            matchedPatterns.add("Para/Ödeme + URL kombinasyonu")
        }
        
        // Aciliyet kelimeleri
        val urgencyWords = listOf("acil", "hemen", "son şans", "bugün", "24 saat", "süresi dol")
        if (urgencyWords.any { message.contains(it, ignoreCase = true) }) {
            riskScore += 15
            matchedPatterns.add("Aciliyet baskısı")
        }
        
        // Kişisel bilgi isteme
        val personalInfoWords = listOf("şifre", "parola", "tc kimlik", "iban", "cvv", "pin")
        if (personalInfoWords.any { message.contains(it, ignoreCase = true) }) {
            riskScore += 30
            matchedPatterns.add("Kişisel bilgi isteme")
        }
        
        // 5. Sonuç
        val confidence = (riskScore / 100f).coerceIn(0f, 1f)
        val isPhishing = riskScore >= 50
        
        val reason = when {
            riskScore >= 80 -> "Yüksek olasılıklı phishing saldırısı"
            riskScore >= 50 -> "Şüpheli mesaj - dikkatli olun"
            riskScore >= 30 -> "Potansiyel risk - doğrulayın"
            else -> "Düşük risk"
        }
        
        val result = AnalysisResult(
            isPhishing = isPhishing,
            confidence = confidence,
            reason = reason,
            matchedPatterns = matchedPatterns
        )
        
        // Phishing ise kaydet
        if (isPhishing) {
            Log.w(TAG, "PHISHING DETECTED from $sender: $reason")
            ThreatDatabase.saveThreat(
                context = context,
                type = "PHISHING_SMS",
                source = "PhishingDetector",
                description = "Phishing SMS tespit edildi - Gönderen: $sender - $reason",
                data = message.take(200),
                severity = if (confidence >= 0.8f) 9 else 7
            )
        }
        
        return@withContext result
    }
    
    /**
     * URL'nin phishing olup olmadığını kontrol et
     */
    fun isPhishingUrl(url: String): Boolean {
        val urlLower = url.lowercase()
        
        // Bilinen phishing domain'leri
        for (domain in KNOWN_PHISHING_DOMAINS) {
            if (urlLower.contains(domain)) {
                return true
            }
        }
        
        // Şüpheli TLD'ler
        val suspiciousTlds = listOf(".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click")
        for (tld in suspiciousTlds) {
            if (urlLower.contains(tld)) {
                return true
            }
        }
        
        // IP adresi URL
        if (url.matches(Regex("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"))) {
            return true
        }
        
        // Homograph saldırısı (benzer karakterler)
        if (url.contains("xn--")) { // Punycode
            return true
        }
        
        return false
    }
    
    /**
     * Metinden URL'leri çıkar
     */
    private fun extractUrls(text: String): List<String> {
        val urlPattern = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
            Pattern.CASE_INSENSITIVE
        )
        
        val matcher = urlPattern.matcher(text)
        val urls = mutableListOf<String>()
        
        while (matcher.find()) {
            urls.add(matcher.group())
        }
        
        return urls
    }
    
    /**
     * URL'yi takip ederek gerçek hedefi bul
     */
    suspend fun resolveUrl(shortUrl: String): String? = withContext(Dispatchers.IO) {
        // TODO: URL çözümleme implementasyonu
        // HTTP HEAD request ile redirect'leri takip et
        null
    }
}
