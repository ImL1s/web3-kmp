package io.github.iml1s.crypto

import java.security.MessageDigest

actual fun platformSha512(data: ByteArray): ByteArray {
    return MessageDigest.getInstance("SHA-512").digest(data)
}
