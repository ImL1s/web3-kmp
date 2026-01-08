package io.github.iml1s.crypto

/**
 * Cosmos (ATOM) Address Generation
 * 
 * Standard: Bech32 (BIP-173)
 * Algorithm: RIPEMD160(SHA256(compressed_pubkey))
 * HRP: "cosmos" for Cosmos Hub, "osmo" for Osmosis, etc.
 * Path: m/44'/118'/0'/0/index
 */
object Cosmos {
    
    const val DEFAULT_HRP = "cosmos"
    const val COIN_TYPE = 118
    
    /**
     * Generate Cosmos address from compressed public key (33 bytes).
     * 
     * @param publicKey Compressed Secp256k1 public key (33 bytes)
     * @param hrp Human-readable prefix (default: "cosmos")
     * @return Bech32 encoded address (e.g., "cosmos1...")
     */
    fun getAddress(publicKey: ByteArray, hrp: String = DEFAULT_HRP): String {
        require(publicKey.size == 33) { "Public key must be 33 bytes (compressed)" }
        
        // 1. SHA256 hash
        val sha256 = Secp256k1Pure.sha256(publicKey)
        
        // 2. RIPEMD160 hash
        val ripemd160 = Ripemd160.hash(sha256)
        
        // 3. Convert to 5-bit words for Bech32
        val words = Bech32.convertBits(ripemd160, 8, 5, true)
        
        // 4. Bech32 encode
        return Bech32.encode(hrp, words, Bech32.Spec.BECH32)
    }
    
    /**
     * Validate a Cosmos Bech32 address
     */
    fun isValidAddress(address: String, expectedHrp: String = DEFAULT_HRP): Boolean {
        return try {
            val decoded = Bech32.decode(address)
            if (decoded.hrp != expectedHrp) return false
            
            val data = Bech32.convertBits(decoded.data, 5, 8, false)
            data.size == 20 // RIPEMD160 output is 20 bytes
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get derivation path for Cosmos
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0/$index"
    }
}
