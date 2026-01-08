package io.github.iml1s.crypto

import java.security.MessageDigest

actual fun platformSha512(data: ByteArray): ByteArray {
    val digest = MessageDigest.getInstance("SHA-512")
    return digest.digest(data)
}
