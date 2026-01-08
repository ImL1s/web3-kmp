package io.github.iml1s.crypto

/**
 * SHA-256 Hash Function
 */
object Sha256 {
    /**
     * compute SHA-256 hash
     *
     * @param data Input data
     * @return 32-byte hash
     */
    fun hash(data: ByteArray): ByteArray {
        val digest = Digests.sha256()
        digest.update(data, 0, data.size)
        val out = ByteArray(digest.getDigestSize())
        digest.doFinal(out, 0)
        return out
    }
}
