package io.github.iml1s.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.cinterop.*
import commonCrypto.*
import platform.CoreCrypto.*
import platform.Security.*
import platform.posix.size_tVar

/**
 * iOS/watchOS 平台實作 - 使用 Apple CommonCrypto 框架
 * 
 * 符合 RFC 5116 標準。
 * 
 * ## 實作細節
 * - 密鑰派生：PBKDF2-HMAC-SHA256
 * - 加密算法：AES-256-GCM
 * - Nonce：12 字節隨機生成 (SecRandomCopyBytes)
 * - Tag：16 字節認證標籤
 * - 支援：iOS 13.0+, watchOS 6.0+
 */
@OptIn(ExperimentalForeignApi::class)
actual object AesGcm {
    actual suspend fun encrypt(
        plaintext: ByteArray,
        password: String,
        salt: ByteArray,
        iterations: Int
    ): AesGcmResult = withContext(Dispatchers.Default) {
        require(plaintext.isNotEmpty()) { "Plaintext cannot be empty" }
        require(password.isNotEmpty()) { "Password cannot be empty" }

        // 1. 派生密鑰 (256-bit)
        val key = pbkdf2HmacSha256(password.encodeToByteArray(), salt, iterations, 32)
        
        // 2. 生成隨機 Nonce (12-byte)
        val nonce = generateSecureRandomBytes(12)
        val ciphertext = ByteArray(plaintext.size)
        val tag = ByteArray(16)

        // 3. 使用 CommonCrypto 進行 GCM 加密
        memScoped {
            val tagLength = alloc<size_tVar>()
            tagLength.value = 16.convert()

            val dummyAAD = alloc<ByteVar>()
            val status = Custom_CCCryptorGCM(
                kCCEncrypt.convert(),
                kCCAlgorithmAES.convert(),
                key.refTo(0), key.size.convert(),
                nonce.refTo(0), nonce.size.convert(),
                dummyAAD.ptr, 0.convert(), // AAD
                plaintext.refTo(0), plaintext.size.convert(),
                ciphertext.refTo(0),
                tag.refTo(0), tagLength.ptr
            )

            if (status != kCCSuccess) {
                throw IllegalStateException("AES-GCM encryption failed with status: $status")
            }
        }

        AesGcmResult(nonce, ciphertext, tag)
    }

    actual suspend fun decrypt(
        encrypted: AesGcmResult,
        password: String,
        salt: ByteArray,
        iterations: Int
    ): ByteArray = withContext(Dispatchers.Default) {
        require(password.isNotEmpty()) { "Password cannot be empty" }

        // 1. 派生相同的密鑰
        val key = pbkdf2HmacSha256(password.encodeToByteArray(), salt, iterations, 32)
        val plaintext = ByteArray(encrypted.ciphertext.size)

        // 2. 使用 CommonCrypto 進行 GCM 解密
        val computedTag = ByteArray(encrypted.tag.size)
        memScoped {
            val tagLength = alloc<size_tVar>()
            tagLength.value = computedTag.size.convert()

            val dummyAAD = alloc<ByteVar>()
            val status = Custom_CCCryptorGCM(
                kCCDecrypt.convert(),
                kCCAlgorithmAES.convert(),
                key.refTo(0), key.size.convert(),
                encrypted.nonce.refTo(0), encrypted.nonce.size.convert(),
                dummyAAD.ptr, 0.convert(),
                encrypted.ciphertext.refTo(0), encrypted.ciphertext.size.convert(),
                plaintext.refTo(0),
                computedTag.refTo(0), tagLength.ptr
            )

            if (status != kCCSuccess) {
                throw IllegalStateException("AES-GCM decryption failed (binary error), status: $status")
            }

            // 3. 手動驗證 Tag (因為 CCCryptorGCM 在某些平台上可能不會自動驗證，而是輸出計算出的 Tag)
            if (!computedTag.contentEquals(encrypted.tag)) {
                throw IllegalStateException("AES-GCM decryption failed (authentication error)")
            }
        }

        plaintext
    }

    /**
     * 生成安全隨機數
     */
    private fun generateSecureRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        val status = SecRandomCopyBytes(kSecRandomDefault, size.convert(), bytes.refTo(0))
        if (status != errSecSuccess) {
            throw IllegalStateException("Failed to generate secure random bytes: $status")
        }
        return bytes
    }
}
