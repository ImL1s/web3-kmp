package io.github.iml1s.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.text.Normalizer

public actual fun platformGetPublicKey(privateKey: ByteArray): ByteArray {
    return Secp256k1Pure.generatePublicKey(privateKey, true)
}

public actual fun platformSha256(data: ByteArray): ByteArray {
    return MessageDigest.getInstance("SHA-256").digest(data)
}

public actual fun platformRipemd160(data: ByteArray): ByteArray {
    return Ripemd160.hash(data)
}

internal actual fun platformHmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}

internal actual fun platformHmacSha512(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(key, "HmacSHA512"))
    return mac.doFinal(data)
}

internal actual fun pbkdf2HmacSha512(
    password: ByteArray,
    salt: ByteArray,
    iterations: Int,
    keyLength: Int
): ByteArray {
    val mac = Mac.getInstance("HmacSHA512")
    mac.init(SecretKeySpec(password, "HmacSHA512"))
    val hLen = 64
    val dkLen = keyLength
    val l = (dkLen + hLen - 1) / hLen
    val dk = ByteArray(l * hLen)
    for (i in 1..l) {
        val block = ByteArray(salt.size + 4)
        System.arraycopy(salt, 0, block, 0, salt.size)
        block[salt.size] = ((i shr 24) and 0xFF).toByte()
        block[salt.size + 1] = ((i shr 16) and 0xFF).toByte()
        block[salt.size + 2] = ((i shr 8) and 0xFF).toByte()
        block[salt.size + 3] = (i and 0xFF).toByte()
        var u = mac.doFinal(block)
        val f = u.copyOf()
        for (j in 2..iterations) {
            u = mac.doFinal(u)
            for (k in f.indices) {
                f[k] = (f[k].toInt() xor u[k].toInt()).toByte()
            }
        }
        System.arraycopy(f, 0, dk, (i - 1) * hLen, hLen)
    }
    return dk.copyOf(dkLen)
}

internal actual fun pbkdf2HmacSha256(
    password: ByteArray,
    salt: ByteArray,
    iterations: Int,
    keyLength: Int
): ByteArray {
    val spec = PBEKeySpec(
        password.decodeToString().toCharArray(),
        salt,
        iterations,
        keyLength * 8
    )
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    return factory.generateSecret(spec).encoded
}

internal actual fun normalizeNfkdPlatform(text: String): String {
    return Normalizer.normalize(text, Normalizer.Form.NFKD)
}

actual object Secp256k1Provider {
    actual fun sign(privateKey: ByteArray, messageHash: ByteArray): ByteArray = Secp256k1Pure.sign(messageHash, privateKey)
    actual fun verify(signature: ByteArray, messageHash: ByteArray, publicKey: ByteArray): Boolean = Secp256k1Pure.verify(messageHash, signature, publicKey)
    actual fun computePublicKey(privateKey: ByteArray, compressed: Boolean): ByteArray = Secp256k1Pure.generatePublicKey(privateKey, compressed)
    actual fun isValidPrivateKey(privateKey: ByteArray): Boolean {
        return try {
            if (privateKey.size != 32) return false
            if (privateKey.all { it == 0.toByte() }) return false
            Secp256k1Pure.generatePublicKey(privateKey)
            true
        } catch (e: Exception) {
            false
        }
    }
    actual fun ecdh(privateKey: ByteArray, publicKey: ByteArray): ByteArray = Secp256k1Pure.ecdh(privateKey, publicKey)
}
