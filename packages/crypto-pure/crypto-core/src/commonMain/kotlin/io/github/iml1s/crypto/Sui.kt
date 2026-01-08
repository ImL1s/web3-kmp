package io.github.iml1s.crypto

/**
 * Sui Address Generation
 * 
 * Algorithm: Blake2b-256(flag | public_key)
 * Flag: 0x00 for Ed25519, 0x01 for Secp256k1, 0x02 for Secp256r1
 * Path: m/44'/784'/0'/0'/0' (SLIP-10, all hardened)
 */
object Sui {
    
    const val COIN_TYPE = 784
    const val FLAG_ED25519: Byte = 0x00
    const val FLAG_SECP256K1: Byte = 0x01
    const val FLAG_SECP256R1: Byte = 0x02
    
    /**
     * Generate Sui address from Ed25519 public key.
     * 
     * @param publicKey Ed25519 public key (32 bytes)
     * @return 66-character hex string with 0x prefix
     */
    fun getAddress(publicKey: ByteArray): String {
        return getAddressWithFlag(publicKey, FLAG_ED25519)
    }
    
    /**
     * Generate Sui address with custom signature scheme flag.
     */
    fun getAddressWithFlag(publicKey: ByteArray, flag: Byte): String {
        val expectedSize = when (flag) {
            FLAG_ED25519 -> 32
            FLAG_SECP256K1 -> 33
            FLAG_SECP256R1 -> 33
            else -> throw IllegalArgumentException("Unknown flag: $flag")
        }
        require(publicKey.size == expectedSize) { "Public key must be $expectedSize bytes for flag $flag" }
        
        // Concatenate flag + public key
        val data = ByteArray(1 + publicKey.size)
        data[0] = flag
        publicKey.copyInto(data, 1)
        
        // Blake2b-256 hash
        val hash = Blake2b.digest(data, digestSize = 32)
        
        return "0x${Hex.encode(hash)}"
    }
    
    /**
     * Validate Sui address format
     */
    fun isValidAddress(address: String): Boolean {
        if (!address.startsWith("0x")) return false
        if (address.length != 66) return false
        
        val hex = address.substring(2)
        return hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }
    
    /**
     * Get derivation path for Sui (SLIP-10, all hardened)
     */
    fun getDerivationPath(account: Int = 0, index: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'/0'/$index'"
    }
}
