package io.github.iml1s.crypto


enum class CardanoNetwork(val id: Int) {
    MAINNET(1),
    TESTNET(0)
}

object Cardano {
    // Shelley Enterprise Address Header (Type 6: 0110)
    // Bits 7-4: 0110 (Enterprise - no stake)
    // Bits 3-0: Network ID
    
    // Mainnet: 0110 0001 = 0x61
    // Testnet: 0110 0000 = 0x60
    
    fun address(publicKey: ByteArray, network: CardanoNetwork = CardanoNetwork.MAINNET): String {
        require(publicKey.size == 32) { "Public key must be 32 bytes (Ed25519)" }
        
        // 1. Hash public key with Blake2b-224
        val keyHash = Blake2b.hash224(publicKey)
        
        // 2. Prepare Header
        val header = if (network == CardanoNetwork.MAINNET) 0x61.toByte() else 0x60.toByte()
        
        // 3. Concatenate Header + KeyHash
        val data = ByteArray(1 + keyHash.size)
        data[0] = header
        keyHash.copyInto(data, 1)
        
        // 4. Bech32 Encode
        // Convert 8-bit bytes to 5-bit words
        val words = Bech32.convertBits(data, 8, 5, true)
        
        val prefix = if (network == CardanoNetwork.MAINNET) "addr" else "addr_test"
        return Bech32.encode(prefix, words, Bech32.Spec.BECH32)
    }
}
