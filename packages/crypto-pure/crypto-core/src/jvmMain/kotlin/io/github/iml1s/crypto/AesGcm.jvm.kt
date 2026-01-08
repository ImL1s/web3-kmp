package io.github.iml1s.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

actual object AesGcm {
    actual suspend fun encrypt(
        plaintext: ByteArray,
        password: String,
        salt: ByteArray,
        iterations: Int
    ): AesGcmResult = withContext(Dispatchers.IO) {
        require(plaintext.isNotEmpty()) { "Plaintext cannot be empty" }
        require(password.isNotEmpty()) { "Password cannot be empty" }

        val key = pbkdf2HmacSha256(password.encodeToByteArray(), salt, iterations, 32)
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, nonce) // 128 bit tag length
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertextWithTag = cipher.doFinal(plaintext)
        
        // Java's GCM implementation appends the tag to the end of the ciphertext
        val tagLength = 16
        val actualCiphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - tagLength)
        val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - tagLength, ciphertextWithTag.size)

        AesGcmResult(nonce, actualCiphertext, tag)
    }

    actual suspend fun decrypt(
        encrypted: AesGcmResult,
        password: String,
        salt: ByteArray,
        iterations: Int
    ): ByteArray = withContext(Dispatchers.IO) {
        require(password.isNotEmpty()) { "Password cannot be empty" }

        val key = pbkdf2HmacSha256(password.encodeToByteArray(), salt, iterations, 32)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, encrypted.nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        // Combine ciphertext and tag for Java's GCM
        val ciphertextWithTag = encrypted.ciphertext + encrypted.tag
        
        try {
            cipher.doFinal(ciphertextWithTag)
        } catch (e: Exception) {
            throw IllegalStateException("AES-GCM decryption failed", e)
        }
    }
}
