package io.github.iml1s.crypto

/**
 * Aptos Address Generation
 * 
 * Algorithm: SHA3-256(public_key | scheme_identifier)
 * Scheme: 0x00 for Ed25519 single-signer
 * Path: m/44'/637'/0'/0'/0' (SLIP-10, all hardened)
 */
object Aptos {
    
    const val COIN_TYPE = 637
    const val SCHEME_ED25519: Byte = 0x00
    const val SCHEME_MULTI_ED25519: Byte = 0x01
    
    /**
     * Generate Aptos address from Ed25519 public key.
     * 
     * @param publicKey Ed25519 public key (32 bytes)
     * @return 66-character hex string with 0x prefix
     */
    fun getAddress(publicKey: ByteArray): String {
        return getAddressWithScheme(publicKey, SCHEME_ED25519)
    }
    
    /**
     * Generate Aptos address with custom scheme identifier.
     * 
     * Formula: SHA3-256(pubkey | scheme)
     */
    fun getAddressWithScheme(publicKey: ByteArray, scheme: Byte): String {
        val expectedSize = when (scheme) {
            SCHEME_ED25519 -> 32
            SCHEME_MULTI_ED25519 -> throw IllegalArgumentException("Multi-Ed25519 requires special handling")
            else -> throw IllegalArgumentException("Unknown scheme: $scheme")
        }
        require(publicKey.size == expectedSize) { "Public key must be $expectedSize bytes" }
        
        // Concatenate pubkey | scheme
        val data = ByteArray(publicKey.size + 1)
        publicKey.copyInto(data, 0)
        data[publicKey.size] = scheme
        
        // SHA3-256 hash
        val hash = Sha3.sha3_256(data)
        
        return "0x${Hex.encode(hash)}"
    }
    
    /**
     * Validate Aptos address format
     */
    fun isValidAddress(address: String): Boolean {
        if (!address.startsWith("0x")) return false
        if (address.length != 66) return false
        
        val hex = address.substring(2)
        return hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }
    
    /**
     * Get derivation path for Aptos (SLIP-10, all hardened)
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0'/$index'"
    }
}
