package io.github.iml1s.crypto

import org.kotlincrypto.hash.sha2.SHA512

actual fun platformSha512(data: ByteArray): ByteArray {
    return SHA512().digest(data)
}
