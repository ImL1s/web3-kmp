package io.github.iml1s.crypto

import kotlin.experimental.and

object Xrp {
    // XRP Base58 Alphabet (starts with 'r')
    const val ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

    /**
     * Get XRP address from public key (Secp256k1 or Ed25519).
     * 
     * Logic:
     * 1. SHA256(pubKey)
     * 2. RIPEMD160(sha256)
     * 3. Add 0x00 version byte (Account ID)
     * 4. Base58Check encode with XRP alphabet
     */
    fun getAddress(publicKey: ByteArray): String {
        // 1. SHA256
        val sha256 = Secp256k1Pure.sha256(publicKey)
        
        // 2. RIPEMD160
        val ripemd160 = Ripemd160.hash(sha256)
        
        // 3. Add Version Byte (0x00 for classic address)
        val payload = ByteArray(1 + ripemd160.size)
        payload[0] = 0x00
        ripemd160.copyInto(payload, 1)
        
        // 4. Base58Check with custom alphabet
        return Base58.encodeWithChecksum(payload, ALPHABET)
    }

    /**
     * Validate XRP address format and checksum
     */
    fun isValidAddress(address: String): Boolean {
        try {
            if (!address.startsWith("r")) return false
            val decoded = Base58.decode(address, ALPHABET)
            
            // Check length (1 byte version + 20 bytes hash + 4 bytes checksum = 25 bytes)
            if (decoded.size != 25) return false
            
            // Check version (0x00) - implicitly checked by starting with 'r', but good strictly
            // Warning: 'r' maps to 0 in this alphabet, so byte 0 must be 0x00.
            if (decoded[0] != 0x00.toByte()) return false

            // Validate Checksum
            val data = decoded.copyOfRange(0, 21)
            val checksum = decoded.copyOfRange(21, 25)
            
            val hash = Secp256k1Pure.sha256(Secp256k1Pure.sha256(data))
            val calculatedChecksum = hash.copyOfRange(0, 4)
            
            return checksum.contentEquals(calculatedChecksum)
        } catch (e: Exception) {
            return false
        }
    }
}
