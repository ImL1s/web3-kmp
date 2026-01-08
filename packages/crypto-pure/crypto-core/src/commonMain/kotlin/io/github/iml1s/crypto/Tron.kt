package io.github.iml1s.crypto

object Tron {
    
    /**
     * Get Tron address from public key (uncompressed, 64 bytes or 65 bytes with 04)
     */
    fun getAddress(publicKey: ByteArray): String {
        // Tron uses Keccak-256 (same as ETH)
        // 1. Get last 20 bytes of Keccak256(pubKey)
        // 2. Prepend 0x41
        // 3. Base58Check encode
        
        val ethAddressBytes = PureEthereumCrypto.getEthereumAddressBytes(publicKey)
        val tronBytes = byteArrayOf(0x41) + ethAddressBytes
        
        return Base58.encodeWithChecksum(tronBytes)

    }
}
