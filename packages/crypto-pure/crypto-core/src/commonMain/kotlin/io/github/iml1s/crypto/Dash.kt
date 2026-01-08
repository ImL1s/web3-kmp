package io.github.iml1s.crypto

/**
 * Dash (DASH) Address Generation
 * 
 * Dash is a Bitcoin fork with different version bytes for addresses.
 * 
 * Address Types:
 * - P2PKH (Pay-to-Public-Key-Hash): Starts with 'X' on mainnet
 * - P2SH (Pay-to-Script-Hash): Starts with '7' on mainnet
 * 
 * Algorithm: Same as Bitcoin - RIPEMD160(SHA256(pubKey)) + Base58Check
 * 
 * Version Bytes:
 * - Mainnet P2PKH: 0x4C (76) -> 'X'
 * - Mainnet P2SH:  0x10 (16) -> '7'
 * - Testnet P2PKH: 0x8C (140) -> 'y'
 * - Testnet P2SH:  0x13 (19) -> '8' or '9'
 * 
 * Path: m/44'/5'/0'/0/index (BIP44, coin_type = 5)
 */
object Dash {
    
    // Mainnet version bytes
    const val MAINNET_P2PKH_VERSION: Byte = 0x4C  // 76 -> 'X'
    const val MAINNET_P2SH_VERSION: Byte = 0x10   // 16 -> '7'
    
    // Testnet version bytes
    const val TESTNET_P2PKH_VERSION: Byte = 0x8C.toByte()  // 140 -> 'y'
    const val TESTNET_P2SH_VERSION: Byte = 0x13   // 19 -> '8' or '9'
    
    // Coin type for BIP44
    const val COIN_TYPE = 5
    
    /**
     * Generate Dash P2PKH address from compressed public key (33 bytes).
     * 
     * @param publicKey Compressed Secp256k1 public key (33 bytes)
     * @param testnet Whether to generate testnet address
     * @return Base58Check encoded address (e.g., "Xo3z...")
     */
    fun getAddress(publicKey: ByteArray, testnet: Boolean = false): String {
        require(publicKey.size == 33 || publicKey.size == 65) { 
            "Public key must be 33 bytes (compressed) or 65 bytes (uncompressed)" 
        }
        
        // 1. SHA256 hash
        val sha256 = Secp256k1Pure.sha256(publicKey)
        
        // 2. RIPEMD160 hash
        val ripemd160 = Ripemd160.hash(sha256)
        
        // 3. Add version byte
        val version = if (testnet) TESTNET_P2PKH_VERSION else MAINNET_P2PKH_VERSION
        val payload = ByteArray(1 + ripemd160.size)
        payload[0] = version
        ripemd160.copyInto(payload, 1)
        
        // 4. Base58Check encode
        return Base58.encodeWithChecksum(payload)
    }
    
    /**
     * Generate Dash P2SH address from script hash (20 bytes).
     * 
     * @param scriptHash RIPEMD160(SHA256(redeemScript))
     * @param testnet Whether to generate testnet address
     * @return Base58Check encoded address (e.g., "7...")
     */
    fun getP2SHAddress(scriptHash: ByteArray, testnet: Boolean = false): String {
        require(scriptHash.size == 20) { "Script hash must be 20 bytes" }
        
        val version = if (testnet) TESTNET_P2SH_VERSION else MAINNET_P2SH_VERSION
        val payload = ByteArray(1 + scriptHash.size)
        payload[0] = version
        scriptHash.copyInto(payload, 1)
        
        return Base58.encodeWithChecksum(payload)
    }
    
    /**
     * Validate a Dash address format and checksum.
     * 
     * @param address Dash address to validate
     * @return true if valid, false otherwise
     */
    fun isValidAddress(address: String): Boolean {
        return try {
            // Check prefix
            val firstChar = address.firstOrNull() ?: return false
            if (firstChar !in listOf('X', '7', 'y', '8', '9')) return false
            
            // Decode and verify checksum
            val decoded = Base58.decode(address)
            
            // Check length (1 byte version + 20 bytes hash + 4 bytes checksum = 25 bytes)
            if (decoded.size != 25) return false
            
            // Verify version byte
            val version = decoded[0]
            val validVersions = listOf(
                MAINNET_P2PKH_VERSION,
                MAINNET_P2SH_VERSION,
                TESTNET_P2PKH_VERSION,
                TESTNET_P2SH_VERSION
            )
            if (version !in validVersions) return false
            
            // Verify checksum
            val data = decoded.copyOfRange(0, 21)
            val providedChecksum = decoded.copyOfRange(21, 25)
            
            val hash = Secp256k1Pure.sha256(Secp256k1Pure.sha256(data))
            val calculatedChecksum = hash.copyOfRange(0, 4)
            
            providedChecksum.contentEquals(calculatedChecksum)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if address is mainnet or testnet.
     * 
     * @param address Dash address
     * @return true if testnet, false if mainnet
     * @throws IllegalArgumentException if address is invalid
     */
    fun isTestnet(address: String): Boolean {
        require(isValidAddress(address)) { "Invalid Dash address" }
        val firstChar = address.first()
        return firstChar in listOf('y', '8', '9')
    }
    
    /**
     * Get derivation path for Dash (BIP44).
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0/$index"
    }
}
