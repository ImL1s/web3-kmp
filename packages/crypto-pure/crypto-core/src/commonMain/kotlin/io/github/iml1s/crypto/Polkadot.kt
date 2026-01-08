package io.github.iml1s.crypto

object Polkadot {

    /**
     * Get Polkadot Address (SS58 Format) from Public Key.
     * 
     * Default Network: Polkadot (0)
     * Generic Substrate: 42
     * Kusama: 2
     */
    fun getAddress(publicKey: ByteArray, networkId: Byte = 0): String {
        return SS58.encode(publicKey, networkId)
    }

    // Ed25519 or Sr25519 Public Key -> Address
}

object SS58 {
    private const val PREFIX = "SS58PRE"
    private val PRE_BYTES = PREFIX.encodeToByteArray()
    
    // Polkadot/Substrate uses standard Bitcoin Base58 alphabet
    
    fun encode(publicKey: ByteArray, network: Byte): String {
        // 1. Prepare data: <network> <public_key>
        val data = ByteArray(1 + publicKey.size)
        data[0] = network
        publicKey.copyInto(data, 1)
        
        // 2. Calculate Checksum: Blake2b-512("SS58PRE" + data)[0..1]
        // Polkadot Spec uses Prefix Concatenation, not Blake2b Personalization param.
        val input = PRE_BYTES + data
        val hash = Blake2b.hash512(input)
        val checksum = hash.copyOfRange(0, 2)
        
        // 3. Encode Base58: <data> <checksum>
        val finalBytes = data + checksum
        
        return Base58.encode(finalBytes)
    }

    fun decode(address: String): Pair<Byte, ByteArray> {
        val decoded = Base58.decode(address)
        val len = decoded.size
        val checksumLen = 2
        val dataLen = len - checksumLen
        
        val data = decoded.copyOfRange(0, dataLen) // <net> <pubkey>
        val providedChecksum = decoded.copyOfRange(dataLen, len)
        
        val input = PRE_BYTES + data
        val hash = Blake2b.hash512(input)
        val calculatedChecksum = hash.copyOfRange(0, checksumLen)
        
        if (!providedChecksum.contentEquals(calculatedChecksum)) {
            throw IllegalArgumentException("Invalid SS58 checksum")
        }
        
        val network = data[0]
        val publicKey = data.copyOfRange(1, data.size)
        
        return Pair(network, publicKey)
    }
}
