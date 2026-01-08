package io.github.iml1s.crypto

/**
 * Zcash (ZEC) Address Generation
 * 
 * This implementation supports transparent addresses only.
 * Shielded addresses (z-addrs) require zk-SNARKs which is beyond scope.
 * 
 * Address Types:
 * - Transparent P2PKH: 
 *   - Mainnet: t1... (prefix bytes: 0x1C, 0xB8)
 *   - Testnet: tm... (prefix bytes: 0x1D, 0x25)
 * - Transparent P2SH:
 *   - Mainnet: t3... (prefix bytes: 0x1C, 0xBD)
 *   - Testnet: t2... (prefix bytes: 0x1C, 0xBA)
 * 
 * Algorithm: Same as Bitcoin but with 2-byte version prefix
 * - RIPEMD160(SHA256(pubKey)) + 2-byte prefix + Base58Check
 * 
 * Path: m/44'/133'/0'/0/index (BIP44, coin_type = 133)
 * 
 * Reference: https://zips.z.cash/protocol/protocol.pdf
 */
object Zcash {
    
    // Mainnet transparent address prefixes (2 bytes)
    val MAINNET_P2PKH_PREFIX = byteArrayOf(0x1C, 0xB8.toByte())  // t1...
    val MAINNET_P2SH_PREFIX = byteArrayOf(0x1C, 0xBD.toByte())   // t3...
    
    // Testnet transparent address prefixes
    val TESTNET_P2PKH_PREFIX = byteArrayOf(0x1D, 0x25)  // tm...
    val TESTNET_P2SH_PREFIX = byteArrayOf(0x1C, 0xBA.toByte())   // t2...
    
    // Coin type for BIP44
    const val COIN_TYPE = 133
    
    /**
     * Generate Zcash transparent P2PKH address from compressed public key.
     * 
     * @param publicKey Compressed Secp256k1 public key (33 bytes)
     * @param testnet Whether to generate testnet address
     * @return Base58Check encoded address (e.g., "t1Rv4exT7...")
     */
    fun getTransparentAddress(publicKey: ByteArray, testnet: Boolean = false): String {
        require(publicKey.size == 33 || publicKey.size == 65) { 
            "Public key must be 33 bytes (compressed) or 65 bytes (uncompressed)" 
        }
        
        // 1. SHA256 hash
        val sha256 = Secp256k1Pure.sha256(publicKey)
        
        // 2. RIPEMD160 hash
        val ripemd160 = Ripemd160.hash(sha256)
        
        // 3. Add 2-byte version prefix
        val prefix = if (testnet) TESTNET_P2PKH_PREFIX else MAINNET_P2PKH_PREFIX
        val payload = ByteArray(prefix.size + ripemd160.size)
        prefix.copyInto(payload, 0)
        ripemd160.copyInto(payload, prefix.size)
        
        // 4. Base58Check encode (double SHA256 checksum)
        return Base58.encodeWithChecksum(payload)
    }
    
    /**
     * Generate Zcash transparent P2SH address from script hash.
     * 
     * @param scriptHash RIPEMD160(SHA256(redeemScript)) - 20 bytes
     * @param testnet Whether to generate testnet address
     * @return Base58Check encoded address (e.g., "t3...")
     */
    fun getP2SHAddress(scriptHash: ByteArray, testnet: Boolean = false): String {
        require(scriptHash.size == 20) { "Script hash must be 20 bytes" }
        
        val prefix = if (testnet) TESTNET_P2SH_PREFIX else MAINNET_P2SH_PREFIX
        val payload = ByteArray(prefix.size + scriptHash.size)
        prefix.copyInto(payload, 0)
        scriptHash.copyInto(payload, prefix.size)
        
        return Base58.encodeWithChecksum(payload)
    }
    
    /**
     * Validate a Zcash transparent address format and checksum.
     * 
     * @param address Zcash address to validate
     * @return true if valid transparent address, false otherwise
     */
    fun isValidAddress(address: String): Boolean {
        return try {
            // Quick prefix check for transparent addresses
            if (!address.startsWith("t")) return false
            
            // Decode Base58
            val decoded = Base58.decode(address)
            
            // Check length (2 bytes prefix + 20 bytes hash + 4 bytes checksum = 26 bytes)
            if (decoded.size != 26) return false
            
            // Extract and verify prefix
            val prefix = decoded.copyOfRange(0, 2)
            val validPrefixes = listOf(
                MAINNET_P2PKH_PREFIX,
                MAINNET_P2SH_PREFIX,
                TESTNET_P2PKH_PREFIX,
                TESTNET_P2SH_PREFIX
            )
            
            val prefixValid = validPrefixes.any { it.contentEquals(prefix) }
            if (!prefixValid) return false
            
            // Verify checksum
            val data = decoded.copyOfRange(0, 22)  // prefix + hash
            val providedChecksum = decoded.copyOfRange(22, 26)
            
            val hash = Secp256k1Pure.sha256(Secp256k1Pure.sha256(data))
            val calculatedChecksum = hash.copyOfRange(0, 4)
            
            providedChecksum.contentEquals(calculatedChecksum)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if address is mainnet or testnet.
     */
    fun isTestnet(address: String): Boolean {
        require(isValidAddress(address)) { "Invalid Zcash address" }
        // Testnet addresses: tm... or t2...
        return address.startsWith("tm") || address.startsWith("t2")
    }
    
    /**
     * Check if address is P2PKH or P2SH.
     */
    fun isP2PKH(address: String): Boolean {
        require(isValidAddress(address)) { "Invalid Zcash address" }
        // P2PKH: t1... or tm...
        return address.startsWith("t1") || address.startsWith("tm")
    }
    
    /**
     * Get derivation path for Zcash (BIP44).
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0/$index"
    }
    
    // ==========================================
    // Sapling (Shielded) Address Support
    // ==========================================
    
    private const val HRP_SAPLING_MAINNET = "zs"
    private const val HRP_SAPLING_TESTNET = "ztestsapling"
    
    /**
     * Encode a Zcash Sapling Shielded Address.
     * 
     * @param diversifier 11-byte diversifier
     * @param pkd 32-byte diversified transmission key (pk_d)
     * @param testnet Whether to generate testnet address
     * @return Bech32 encoded string (e.g., "zs1...")
     */
    fun encodeSaplingAddress(diversifier: ByteArray, pkd: ByteArray, testnet: Boolean = false): String {
        require(diversifier.size == 11) { "Diversifier must be 11 bytes" }
        require(pkd.size == 32) { "pk_d must be 32 bytes" }
        
        val data = diversifier + pkd
        
        // Convert 8-bit data to 5-bit for Bech32
        val data5bit = Bech32.convertBits(data, 8, 5, true)
        val hrp = if (testnet) HRP_SAPLING_TESTNET else HRP_SAPLING_MAINNET
        
        return Bech32.encode(hrp, data5bit, Bech32.Spec.BECH32)
    }
    
    /**
     * Decode a Zcash Sapling Shielded Address.
     * 
     * @param address Bech32 encoded address
     * @return Pair of (diversifier[11], pk_d[32])
     */
    fun decodeSaplingAddress(address: String): Pair<ByteArray, ByteArray> {
        val decoded = Bech32.decode(address)
        
        require(decoded.hrp == HRP_SAPLING_MAINNET || decoded.hrp == HRP_SAPLING_TESTNET) {
            "Invalid Sapling HRP: ${decoded.hrp}"
        }
        
        // Convert 5-bit back to 8-bit
        val data = Bech32.convertBits(decoded.data, 5, 8, false)
        require(data.size == 43) { "Invalid Sapling payload length: ${data.size}" }
        
        val diversifier = data.copyOfRange(0, 11)
        val pkd = data.copyOfRange(11, 43)
        
        return Pair(diversifier, pkd)
    }
}
