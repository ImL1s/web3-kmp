package io.github.iml1s.crypto

/**
 * Monero (XMR) Address Generation
 * 
 * Monero uses a unique address format with two Ed25519 public keys:
 * - Spend Public Key: Used to construct transaction outputs
 * - View Public Key: Used to scan blockchain for incoming transactions
 * 
 * Address Types:
 * - Standard (Primary): Starts with '4' (mainnet), '9' (testnet/stagenet)
 * - Subaddress: Starts with '8' (mainnet), 'B' (testnet/stagenet)
 * - Integrated: 106 characters, contains payment ID
 * 
 * Format: Base58-Monero(networkByte + spendKey[32] + viewKey[32] + checksum[4])
 * - Total raw: 1 + 32 + 32 + 4 = 69 bytes
 * - Encoded: 95 characters for standard address
 * 
 * Checksum: First 4 bytes of Keccak256(networkByte + spendKey + viewKey)
 * 
 * Path: m/44'/128'/0'/0/index (SLIP-0044, coin_type = 128)
 * Note: Monero uses a non-BIP44 derivation for subaddresses
 * 
 * Reference: https://monerodocs.org/public-address/standard-address/
 */
object Monero {
    
    // Network bytes
    const val MAINNET_STANDARD: Byte = 0x12    // 18 -> '4'
    const val MAINNET_SUBADDRESS: Byte = 0x2A  // 42 -> '8'
    const val MAINNET_INTEGRATED: Byte = 0x13  // 19 -> '4' (106 chars)
    
    const val TESTNET_STANDARD: Byte = 0x35    // 53 -> '9'
    const val TESTNET_SUBADDRESS: Byte = 0x3F  // 63 -> 'B'
    const val TESTNET_INTEGRATED: Byte = 0x36  // 54 -> 'A'
    
    const val STAGENET_STANDARD: Byte = 0x18   // 24 -> '5'
    const val STAGENET_SUBADDRESS: Byte = 0x24 // 36 -> '7'
    const val STAGENET_INTEGRATED: Byte = 0x19 // 25 -> '5'
    
    // Coin type for SLIP-0044
    const val COIN_TYPE = 128
    
    /**
     * Generate Monero standard address from spend and view public keys.
     * 
     * @param spendPublicKey Ed25519 public key for spending (32 bytes)
     * @param viewPublicKey Ed25519 public key for viewing (32 bytes)
     * @param network Network type: "mainnet", "testnet", or "stagenet"
     * @return Base58-Monero encoded address (95 characters for standard)
     */
    fun getAddress(
        spendPublicKey: ByteArray,
        viewPublicKey: ByteArray,
        network: String = "mainnet"
    ): String {
        require(spendPublicKey.size == 32) { "Spend public key must be 32 bytes" }
        require(viewPublicKey.size == 32) { "View public key must be 32 bytes" }
        
        val networkByte = when (network.lowercase()) {
            "mainnet" -> MAINNET_STANDARD
            "testnet" -> TESTNET_STANDARD
            "stagenet" -> STAGENET_STANDARD
            else -> throw IllegalArgumentException("Unknown network: $network")
        }
        
        return encodeAddress(networkByte, spendPublicKey, viewPublicKey)
    }
    
    /**
     * Generate Monero subaddress.
     * 
     * @param spendPublicKey Ed25519 public key for spending (32 bytes)
     * @param viewPublicKey Ed25519 public key for viewing (32 bytes)
     * @param network Network type
     * @return Base58-Monero encoded subaddress (95 characters)
     */
    fun getSubaddress(
        spendPublicKey: ByteArray,
        viewPublicKey: ByteArray,
        network: String = "mainnet"
    ): String {
        require(spendPublicKey.size == 32) { "Spend public key must be 32 bytes" }
        require(viewPublicKey.size == 32) { "View public key must be 32 bytes" }
        
        val networkByte = when (network.lowercase()) {
            "mainnet" -> MAINNET_SUBADDRESS
            "testnet" -> TESTNET_SUBADDRESS
            "stagenet" -> STAGENET_SUBADDRESS
            else -> throw IllegalArgumentException("Unknown network: $network")
        }
        
        return encodeAddress(networkByte, spendPublicKey, viewPublicKey)
    }
    
    /**
     * Generate Monero integrated address with payment ID.
     * 
     * @param spendPublicKey Ed25519 public key for spending (32 bytes)
     * @param viewPublicKey Ed25519 public key for viewing (32 bytes)
     * @param paymentId 8-byte payment ID
     * @param network Network type
     * @return Base58-Monero encoded integrated address (106 characters)
     */
    fun getIntegratedAddress(
        spendPublicKey: ByteArray,
        viewPublicKey: ByteArray,
        paymentId: ByteArray,
        network: String = "mainnet"
    ): String {
        require(spendPublicKey.size == 32) { "Spend public key must be 32 bytes" }
        require(viewPublicKey.size == 32) { "View public key must be 32 bytes" }
        require(paymentId.size == 8) { "Payment ID must be 8 bytes" }
        
        val networkByte = when (network.lowercase()) {
            "mainnet" -> MAINNET_INTEGRATED
            "testnet" -> TESTNET_INTEGRATED
            "stagenet" -> STAGENET_INTEGRATED
            else -> throw IllegalArgumentException("Unknown network: $network")
        }
        
        // Format: networkByte + spendKey + viewKey + paymentId + checksum
        val data = ByteArray(1 + 32 + 32 + 8)
        data[0] = networkByte
        spendPublicKey.copyInto(data, 1)
        viewPublicKey.copyInto(data, 33)
        paymentId.copyInto(data, 65)
        
        val checksum = Keccak256.hash(data).copyOfRange(0, 4)
        val fullData = data + checksum
        
        return MoneroBase58.encode(fullData)
    }
    
    private fun encodeAddress(
        networkByte: Byte,
        spendPublicKey: ByteArray,
        viewPublicKey: ByteArray
    ): String {
        // Format: networkByte + spendKey + viewKey + checksum
        val data = ByteArray(1 + 32 + 32)
        data[0] = networkByte
        spendPublicKey.copyInto(data, 1)
        viewPublicKey.copyInto(data, 33)
        
        // Checksum: first 4 bytes of Keccak256(data)
        val checksum = Keccak256.hash(data).copyOfRange(0, 4)
        val fullData = data + checksum
        
        return MoneroBase58.encode(fullData)
    }
    
    /**
     * Validate a Monero address format and checksum.
     * 
     * @param address Monero address to validate
     * @return true if valid, false otherwise
     */
    fun isValidAddress(address: String): Boolean {
        return try {
            // Check length
            val validLengths = listOf(95, 106)  // Standard/Subaddress or Integrated
            if (address.length !in validLengths) return false
            
            // Check prefix
            val firstChar = address.firstOrNull() ?: return false
            val validPrefixes = listOf('4', '8', '9', 'B', '5', '7', 'A')
            if (firstChar !in validPrefixes) return false
            
            // Decode and verify checksum
            val decoded = MoneroBase58.decode(address)
            
            // Expected sizes: 69 (standard) or 77 (integrated)
            if (decoded.size != 69 && decoded.size != 77) return false
            
            // Verify network byte
            val networkByte = decoded[0]
            val validNetworkBytes = listOf(
                MAINNET_STANDARD, MAINNET_SUBADDRESS, MAINNET_INTEGRATED,
                TESTNET_STANDARD, TESTNET_SUBADDRESS, TESTNET_INTEGRATED,
                STAGENET_STANDARD, STAGENET_SUBADDRESS, STAGENET_INTEGRATED
            )
            if (networkByte !in validNetworkBytes) return false
            
            // Verify checksum
            val dataLength = decoded.size - 4
            val data = decoded.copyOfRange(0, dataLength)
            val providedChecksum = decoded.copyOfRange(dataLength, decoded.size)
            
            val calculatedChecksum = Keccak256.hash(data).copyOfRange(0, 4)
            
            providedChecksum.contentEquals(calculatedChecksum)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Decode a Monero address to extract its components.
     * 
     * @param address Monero address
     * @return Triple of (network byte, spend public key, view public key)
     * @throws IllegalArgumentException if address is invalid
     */
    fun decodeAddress(address: String): Triple<Byte, ByteArray, ByteArray> {
        require(isValidAddress(address)) { "Invalid Monero address" }
        
        val decoded = MoneroBase58.decode(address)
        
        val networkByte = decoded[0]
        val spendPublicKey = decoded.copyOfRange(1, 33)
        val viewPublicKey = decoded.copyOfRange(33, 65)
        
        return Triple(networkByte, spendPublicKey, viewPublicKey)
    }
    
    /**
     * Get the network type from an address.
     */
    fun getNetwork(address: String): String {
        require(isValidAddress(address)) { "Invalid Monero address" }
        
        val decoded = MoneroBase58.decode(address)
        val networkByte = decoded[0]
        
        return when (networkByte) {
            MAINNET_STANDARD, MAINNET_SUBADDRESS, MAINNET_INTEGRATED -> "mainnet"
            TESTNET_STANDARD, TESTNET_SUBADDRESS, TESTNET_INTEGRATED -> "testnet"
            STAGENET_STANDARD, STAGENET_SUBADDRESS, STAGENET_INTEGRATED -> "stagenet"
            else -> throw IllegalStateException("Unknown network byte: $networkByte")
        }
    }
    
    /**
     * Check if address is a subaddress.
     */
    fun isSubaddress(address: String): Boolean {
        require(isValidAddress(address)) { "Invalid Monero address" }
        
        val decoded = MoneroBase58.decode(address)
        val networkByte = decoded[0]
        
        return networkByte in listOf(MAINNET_SUBADDRESS, TESTNET_SUBADDRESS, STAGENET_SUBADDRESS)
    }
    
    /**
     * Check if address is an integrated address.
     */
    fun isIntegratedAddress(address: String): Boolean {
        require(isValidAddress(address)) { "Invalid Monero address" }
        return address.length == 106
    }
    
    /**
     * Get derivation path for Monero (SLIP-0044).
     * Note: Monero's actual key derivation differs from standard BIP44.
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0/$index"
    }
}
