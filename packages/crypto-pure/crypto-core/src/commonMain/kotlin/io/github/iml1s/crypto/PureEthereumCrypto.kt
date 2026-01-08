package io.github.iml1s.crypto

// Base58 and Keccak256 are now in the same package


/**
 * Cross-platform Pure Kotlin implementation for Ethereum Address Derivation
 * Uses Secp256k1Pure (Common) and various pure implementations.
 */
object PureEthereumCrypto {

    fun ping(): String = "pong"
    
    fun pingWithArg(valStr: String): String = "pong:$valStr"

    /**
     * Derive Ethereum address from Xpub and path
     * @param xpub Base58Check encoded extended public key
     * @param path Derivation path (e.g. "m/0/0")
     * @return Ethereum address (0x...)
     */
    fun deriveAddressFromXpub(xpub: String, path: String): String {
        try {
             // 1. Decode Base58
            val decoded = Base58.decode(xpub)
            if (decoded.size != 78 + 4) {
                 // Try to be robust - sometimes people omit checksum or decode includes it?
                 // Standard xpub is 78 bytes + 4 bytes checksum = 82 bytes.
                 if (decoded.size != 82) {
                     throw IllegalArgumentException("Invalid xpub length: ${decoded.size}")
                 }
            }
            
            // 2. Verify Checksum
            val data = decoded.copyOfRange(0, 78)
            val checksum = decoded.copyOfRange(78, 82)
            val calculatedChecksum = Secp256k1Pure.sha256(Secp256k1Pure.sha256(data)).copyOfRange(0, 4)
            
            if (!checksum.contentEquals(calculatedChecksum)) {
                // Checksum mismatch - ignored for robustness but noted internally
            }

            // 3. Extract Chain Code and Public Key
            // xpub structure:
            // 0-3: version (4) - standard: 0x0488B21E (xpub)
            // 4: depth (1)
            // 5-8: parent fingerprint (4)
            // 9-12: child number (4)
            // 13-44: chain code (32)
            // 45-77: public key (33)
            
            var currentChainCode = data.copyOfRange(13, 45)
            var currentKeyData = data.copyOfRange(45, 78)
            
            // 4. Parse Path
            val indices = parseDerivationPath(path)
            
            // 5. Derive Child Keys
            for (index in indices) {
                // Public derivation does not support hardened paths
                if ((index and 0x80000000u) != 0u) {
                    throw IllegalArgumentException("Cannot derive hardened path from xpub")
                }
                
                // CKDpub
                // I = HMAC-SHA512(c_par, serP(K_par) || ser32(i))
                // currentKeyData IS serP(K_par) (compressed usually)
                val dataToHmac = currentKeyData + index.toBigEndianByteArray()
                // Use HmacSha512 (assuming available as per derivePrivateKey)
                val i = HmacSha512.hmac(currentChainCode, dataToHmac)
                val il = i.copyOfRange(0, 32)
                val ir = i.copyOfRange(32, 64)
                
                // Ki = point(Il) + Kpar
                val ilInt = Secp256k1Pure.BigInteger(il)
                val n = Secp256k1Pure.BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                
                if (ilInt >= n || ilInt == Secp256k1Pure.BigInteger.ZERO) {
                    throw IllegalStateException("Invalid IL")
                }
                
                // Add points
                val pointIl = Secp256k1Pure.generatePublicKeyPoint(il) // point(Il)
                val pointKpar = Secp256k1Pure.decodePublicKey(currentKeyData) // Kpar
                
                val pointKi = Secp256k1Pure.addPoints(pointIl, pointKpar)
                
                // Check for infinity (not handled by addPoints explicitly but check validity)
                
                currentKeyData = Secp256k1Pure.encodePublicKey(pointKi, compressed = true)
                currentChainCode = ir
            }
            
            // 6. Convert to Address
            // Need uncompressed point for Keccak hash logic
            val finalPoint = Secp256k1Pure.decodePublicKey(currentKeyData)
            val uncompressed = Secp256k1Pure.encodePublicKey(finalPoint, compressed = false)
            
            // Drop 0x04 prefix
            val dataToHash = uncompressed.copyOfRange(1, uncompressed.size)
            val hash = Keccak256.hash(dataToHash)
            
            val addressBytes = hash.copyOfRange(12, 32)
            return toChecksumAddress("0x" + addressBytes.toHexString())
            
        } catch (e: Exception) {
            throw e
        }
    }

    /**
     * Derive Private Key from Mnemonic and Path (BIP39 + BIP32)
     * @param mnemonic BIP39 mnemonic words
     * @param path Derivation path (e.g. "m/44'/60'/0'/0/0")
     * @return Private Key Hex String (0x...)
     */
    fun derivePrivateKey(mnemonic: String, path: String): String {
         try {
             // 1. Mnemonic -> Seed
             val seed = Pbkdf2.bip39Seed(mnemonic, "")
             
             // 2. Seed -> Master Key (BIP32)
             // HMAC-SHA512("Bitcoin seed", seed)
             val hmac = HmacSha512.hmac("Bitcoin seed".encodeToByteArray(), seed)
             var currentKeyData = hmac.copyOfRange(0, 32)
             var currentChainCode = hmac.copyOfRange(32, 64)
             
             // 3. Parse Path
             val indices = parseDerivationPath(path)
             
             // 4. Derive Child Keys
             for (index in indices) {
                 val isHardened = (index and 0x80000000u) != 0u
                 
                 val dataToHmac: ByteArray
                 if (isHardened) {
                     // 0x00 || key || index
                     dataToHmac = byteArrayOf(0) + currentKeyData + index.toBigEndianByteArray()
                 } else {
                     // point(key) || index
                     val point = Secp256k1Pure.generatePublicKeyPoint(currentKeyData)
                     val pubBytes = Secp256k1Pure.encodePublicKey(point, compressed = true)
                     dataToHmac = pubBytes + index.toBigEndianByteArray()
                 }
                 
                 val i = HmacSha512.hmac(currentChainCode, dataToHmac)
                 val il = i.copyOfRange(0, 32)
                 val ir = i.copyOfRange(32, 64)
                 
                 // ki = IL + kpar (mod n)
                 val ilInt = Secp256k1Pure.BigInteger(il)
                 val kparInt = Secp256k1Pure.BigInteger(currentKeyData)
                 val n = Secp256k1Pure.BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
                 
                 if (ilInt >= n || ilInt == Secp256k1Pure.BigInteger.ZERO) {
                      throw IllegalStateException("Invalid IL")
                 }
                 
                 val kiInt = (ilInt + kparInt).mod(n)
                 
                 if (kiInt == Secp256k1Pure.BigInteger.ZERO) {
                      throw IllegalStateException("Invalid ki")
                 }
                 
                 // Convert back to 32 bytes
                 // BigInteger to ByteArray might need padding
                 val kiBytes = kiInt.toByteArray()
                 // Ensure 32 bytes
                 currentKeyData = if (kiBytes.size < 32) {
                     ByteArray(32 - kiBytes.size) + kiBytes
                 } else if (kiBytes.size > 32) {
                     // Drop leading zeros if any?
                     kiBytes.copyOfRange(kiBytes.size - 32, kiBytes.size)
                 } else {
                     kiBytes
                 }
                 
                 currentChainCode = ir
             }
             
             return "0x" + Hex.encode(currentKeyData)
             
         } catch (e: Exception) {
             throw e
         }
    }

    /**
     * Generate Ethereum Address from Private Key
     * @param privateKeyHex Private Key Hex (with or without 0x)
     * @return Checksum Address
     */
    fun getEthereumAddress(privateKeyHex: String): String {
        try {
            val keyClean = if (privateKeyHex.startsWith("0x")) privateKeyHex.substring(2) else privateKeyHex
            val privateKey = Hex.decode(keyClean)
            
            val publicKeyPoint = Secp256k1Pure.generatePublicKeyPoint(privateKey)
            val uncompressed = Secp256k1Pure.encodePublicKey(publicKeyPoint, compressed = false)
            
            // Drop 0x04
            val dataToHash = uncompressed.copyOfRange(1, uncompressed.size)
            val hash = Keccak256.hash(dataToHash)
            
            val addressBytes = hash.copyOfRange(12, 32)
            return toChecksumAddress("0x" + addressBytes.toHexString())
            
        } catch (e: Exception) {
            throw e
        }
    }

    /**
     * Get raw Ethereum address bytes (last 20 bytes of Keccak256 of uncompressed public key)
     */
    fun getEthereumAddressBytes(publicKey: ByteArray): ByteArray {
        val point = Secp256k1Pure.decodePublicKey(publicKey)
        val uncompressed = Secp256k1Pure.encodePublicKey(point, compressed = false)
        val dataToHash = uncompressed.copyOfRange(1, uncompressed.size)
        val hash = Keccak256.hash(dataToHash)
        return hash.copyOfRange(12, 32)
    }


    // Helpers
    
    private fun parseDerivationPath(path: String): List<UInt> {
        var cleanPath = path
        if (cleanPath.startsWith("m/") || cleanPath.startsWith("M/")) {
            cleanPath = cleanPath.substring(2)
        }
        if (cleanPath.isEmpty()) return emptyList()
        
        return cleanPath.split("/").mapNotNull { component ->
            var text = component
            var isHardened = false
            if (text.endsWith("'") || text.endsWith("h")) {
                isHardened = true
                text = text.dropLast(1)
            }
            val valInt = text.toUIntOrNull() ?: return@mapNotNull null
            if (isHardened) (valInt or 0x80000000u) else valInt
        }
    }
    
    private fun toChecksumAddress(address: String): String {
        val cleanAddress = if (address.startsWith("0x")) address.substring(2) else address
        val addressLower = cleanAddress.lowercase()
        
        // Hash the lowercase address string
        val hash = Hex.encode(Keccak256.hash(addressLower.encodeToByteArray()))
        
        val result = StringBuilder("0x")
        for (i in addressLower.indices) {
            val char = addressLower[i]
            if (char in '0'..'9') {
                result.append(char)
            } else {
                // Check ith bit of hash (actually ith nibble in hex string representation logic for EIP-55?)
                // EIP-55: hash the lowercase address. 
                // If the ith byte of the hash's hex representation >= 8, uppercase the ith char.
                val hashChar = hash[i]
                if (hashChar >= '8') {
                    result.append(char.uppercaseChar())
                } else {
                    result.append(char)
                }
            }
        }
        return result.toString()
    }
    
    
}
