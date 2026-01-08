package io.github.iml1s.crypto

/**
 * Avalanche Address Generation
 * 
 * Supports both C-Chain (EVM) and X-Chain (Bech32) formats.
 * 
 * C-Chain: Ethereum-compatible (0x...)
 * X-Chain: Bech32 with "avax" HRP (X-avax1...)
 * P-Chain: Same as X-Chain (P-avax1...)
 */
object Avalanche {
    
    const val X_CHAIN_HRP = "avax"
    const val COIN_TYPE = 9000
    
    /**
     * Generate C-Chain address (Ethereum-compatible).
     * Uses same derivation as Ethereum: m/44'/60'/0'/0/index
     * 
     * @param publicKey Uncompressed Secp256k1 public key (64 or 65 bytes)
     * @return Ethereum-style address with 0x prefix
     */
    fun getCChainAddress(publicKey: ByteArray): String {
        val addressBytes = PureEthereumCrypto.getEthereumAddressBytes(publicKey)
        return "0x${Hex.encode(addressBytes)}"
    }
    
    /**
     * Generate X-Chain address (Bech32).
     * Uses: RIPEMD160(SHA256(compressed_pubkey))
     * 
     * @param publicKey Compressed Secp256k1 public key (33 bytes)
     * @return Address with X- prefix (e.g., "X-avax1...")
     */
    fun getXChainAddress(publicKey: ByteArray): String {
        require(publicKey.size == 33) { "Public key must be 33 bytes (compressed)" }
        
        // Same hash as Cosmos/Bitcoin
        val sha256 = Secp256k1Pure.sha256(publicKey)
        val ripemd160 = Ripemd160.hash(sha256)
        
        val words = Bech32.convertBits(ripemd160, 8, 5, true)
        val bech32 = Bech32.encode(X_CHAIN_HRP, words, Bech32.Spec.BECH32)
        
        return "X-$bech32"
    }
    
    /**
     * Generate P-Chain address (same format as X-Chain).
     */
    fun getPChainAddress(publicKey: ByteArray): String {
        require(publicKey.size == 33) { "Public key must be 33 bytes (compressed)" }
        
        val sha256 = Secp256k1Pure.sha256(publicKey)
        val ripemd160 = Ripemd160.hash(sha256)
        
        val words = Bech32.convertBits(ripemd160, 8, 5, true)
        val bech32 = Bech32.encode(X_CHAIN_HRP, words, Bech32.Spec.BECH32)
        
        return "P-$bech32"
    }
    
    /**
     * Validate X-Chain or P-Chain address
     */
    fun isValidXPAddress(address: String): Boolean {
        return try {
            if (!address.startsWith("X-") && !address.startsWith("P-")) return false
            
            val bech32Part = address.substring(2)
            val decoded = Bech32.decode(bech32Part)
            
            if (decoded.hrp != X_CHAIN_HRP) return false
            
            val data = Bech32.convertBits(decoded.data, 5, 8, false)
            data.size == 20
        } catch (e: Exception) {
            false
        }
    }
}
