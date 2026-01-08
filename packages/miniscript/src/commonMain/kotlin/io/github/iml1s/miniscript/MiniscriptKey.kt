package io.github.iml1s.miniscript

/**
 * Trait representing a key which can be converted to a hash type.
 */
interface MiniscriptKey {
    val isUncompressed: Boolean get() = false
    val isXOnly: Boolean
    val numDerPaths: Int get() = 0

    // Associated types are handled via generics or specific implementations in Kotlin.
    // In Rust: type Sha256, Hash256, Ripemd160, Hash160
    // We will use ByteArray or specific Hash types for these.
    
    // For simplicity in Kotlin, we might just return the hash bytes directly or wrapped types.
    // Let's assume standard ByteArray for hashes for now, or define a Hash interface if needed.
}

interface ToPublicKey : MiniscriptKey {
    fun toPublicKey(): ByteArray
    
    fun toHash256(hash: ByteArray): ByteArray
    fun toRipemd160(hash: ByteArray): ByteArray
    fun toHash160(hash: ByteArray): ByteArray
}

data class StringKey(val content: String) : ToPublicKey {
    override val isXOnly: Boolean = false
    override fun toString(): String = content
    override fun toPublicKey(): ByteArray {
        return try {
            io.github.iml1s.crypto.Hex.decode(content)
        } catch (e: Exception) {
            content.encodeToByteArray()
        }
    }
    override fun toHash256(hash: ByteArray): ByteArray {
        val digest = io.github.iml1s.crypto.Digests.sha256()
        val d1 = ByteArray(digest.getDigestSize())
        digest.update(toPublicKey(), 0, toPublicKey().size)
        digest.doFinal(d1, 0)
        digest.reset()
        val d2 = ByteArray(digest.getDigestSize())
        digest.update(d1, 0, d1.size)
        digest.doFinal(d2, 0)
        return d2
    }
    
    override fun toRipemd160(hash: ByteArray): ByteArray {
         return io.github.iml1s.crypto.Ripemd160.hash(toPublicKey())
    }

    override fun toHash160(hash: ByteArray): ByteArray {
        val digest = io.github.iml1s.crypto.Digests.sha256()
        val d1 = ByteArray(digest.getDigestSize())
        digest.update(toPublicKey(), 0, toPublicKey().size)
        digest.doFinal(d1, 0)
        return io.github.iml1s.crypto.Ripemd160.hash(d1)
    }
}
