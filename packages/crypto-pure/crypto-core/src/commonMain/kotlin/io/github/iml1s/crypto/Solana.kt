package io.github.iml1s.crypto

import io.github.andreypfau.curve25519.ed25519.Ed25519
import io.github.andreypfau.curve25519.ed25519.Ed25519PublicKey
import kotlin.random.Random

data class SolanaKeyPair(val privateKey: ByteArray, val publicKey: ByteArray)

object Solana {
    
    /**
     * Generate new KeyPair
     */
    fun generateKeyPair(): SolanaKeyPair {
        val seed = ByteArray(32)
        Random.nextBytes(seed)
        val privateKeyObj = Ed25519.keyFromSeed(seed)
        val publicKeyObj = privateKeyObj.publicKey()
        return SolanaKeyPair(seed, publicKeyObj.toByteArray())
    }

    /**
     * Derive Public Key from Private Key (Seed)
     */
    fun derivePublicKey(privateKey: ByteArray): ByteArray {
        return Ed25519.keyFromSeed(privateKey).publicKey().toByteArray()
    }

    /**
     * Sign message
     */
    fun sign(message: ByteArray, privateKey: ByteArray): ByteArray {
        val privateKeyObj = Ed25519.keyFromSeed(privateKey)
        return privateKeyObj.sign(message)
    }

    /**
     * Verify signature
     */
    fun verify(message: ByteArray, signature: ByteArray, pubKey: ByteArray): Boolean {
        val publicKeyObj = Ed25519PublicKey(pubKey)
        return publicKeyObj.verify(message, signature)
    }





    
    /**
     * Get address from public key
     */
    fun getAddress(publicKey: ByteArray): String {
        return Base58.encode(publicKey)
    }
}
