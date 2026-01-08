package io.github.iml1s.crypto

/**
 * SHA-512 Hash Function
 *
 * Provides a common interface for SHA-512 hashing across platforms.
 */
object Sha512 {
    /**
     * compute SHA-512 hash
     *
     * @param data Input data
     * @return 64-byte hash
     */
    fun hash(data: ByteArray): ByteArray {
        return platformSha512(data)
    }
}

/**
 * Platform-specific SHA-512 implementation
 */
expect fun platformSha512(data: ByteArray): ByteArray
