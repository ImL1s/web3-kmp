package io.github.iml1s.crypto

/**
 * Monero Base58 Encoding
 * 
 * Monero uses a unique Base58 variant that differs from Bitcoin's:
 * - Same alphabet as Bitcoin (excludes 0, O, I, l)
 * - Block-based encoding: 8 bytes → 11 characters
 * - Last block may be shorter
 * - No checksum in the encoding itself (checksum is part of the data)
 * 
 * Reference: https://monerodocs.org/cryptography/base58/
 */
object MoneroBase58 {
    
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private val ALPHABET_MAP: Map<Char, Int> = ALPHABET.mapIndexed { i, c -> c to i }.toMap()
    
    // Full block: 8 bytes → 11 characters
    private const val FULL_BLOCK_SIZE = 8
    private const val FULL_ENCODED_BLOCK_SIZE = 11
    
    // Partial block sizes (bytes → chars)
    private val ENCODED_BLOCK_SIZES = intArrayOf(0, 2, 3, 5, 6, 7, 9, 10, 11)
    
    /**
     * Encode bytes to Monero Base58.
     * 
     * @param data Raw bytes to encode
     * @return Base58 encoded string
     */
    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        
        val sb = StringBuilder()
        val fullBlockCount = data.size / FULL_BLOCK_SIZE
        val lastBlockSize = data.size % FULL_BLOCK_SIZE
        
        // Encode full blocks
        for (i in 0 until fullBlockCount) {
            val block = data.copyOfRange(i * FULL_BLOCK_SIZE, (i + 1) * FULL_BLOCK_SIZE)
            sb.append(encodeBlock(block, FULL_ENCODED_BLOCK_SIZE))
        }
        
        // Encode last partial block
        if (lastBlockSize > 0) {
            val block = data.copyOfRange(fullBlockCount * FULL_BLOCK_SIZE, data.size)
            sb.append(encodeBlock(block, ENCODED_BLOCK_SIZES[lastBlockSize]))
        }
        
        return sb.toString()
    }
    
    /**
     * Decode Monero Base58 string to bytes.
     * 
     * @param encoded Base58 encoded string
     * @return Decoded bytes
     */
    fun decode(encoded: String): ByteArray {
        if (encoded.isEmpty()) return ByteArray(0)
        
        val result = mutableListOf<Byte>()
        val fullBlockCount = encoded.length / FULL_ENCODED_BLOCK_SIZE
        val lastEncodedBlockSize = encoded.length % FULL_ENCODED_BLOCK_SIZE
        
        // Decode full blocks
        for (i in 0 until fullBlockCount) {
            val block = encoded.substring(
                i * FULL_ENCODED_BLOCK_SIZE, 
                (i + 1) * FULL_ENCODED_BLOCK_SIZE
            )
            result.addAll(decodeBlock(block, FULL_BLOCK_SIZE).toList())
        }
        
        // Decode last partial block
        if (lastEncodedBlockSize > 0) {
            val block = encoded.substring(fullBlockCount * FULL_ENCODED_BLOCK_SIZE)
            val lastBlockSize = ENCODED_BLOCK_SIZES.indexOf(lastEncodedBlockSize)
            if (lastBlockSize < 0) {
                throw IllegalArgumentException("Invalid Monero Base58 string length")
            }
            result.addAll(decodeBlock(block, lastBlockSize).toList())
        }
        
        return result.toByteArray()
    }
    
    private fun encodeBlock(block: ByteArray, encodedSize: Int): String {
        // Convert block to big integer
        var num = 0UL
        for (byte in block) {
            num = num * 256UL + (byte.toInt() and 0xFF).toUInt().toULong()
        }
        
        // Convert to base58
        val chars = CharArray(encodedSize) { '1' }  // Pad with '1' (value 0)
        var idx = encodedSize - 1
        while (num > 0UL && idx >= 0) {
            val remainder = (num % 58UL).toInt()
            chars[idx] = ALPHABET[remainder]
            num /= 58UL
            idx--
        }
        
        return chars.concatToString()
    }
    
    private fun decodeBlock(block: String, decodedSize: Int): ByteArray {
        // Convert from base58
        var num = 0UL
        for (char in block) {
            val value = ALPHABET_MAP[char]
                ?: throw IllegalArgumentException("Invalid character in Monero Base58: $char")
            num = num * 58UL + value.toULong()
        }
        
        // Convert to bytes (big-endian)
        val result = ByteArray(decodedSize)
        for (i in decodedSize - 1 downTo 0) {
            result[i] = (num and 0xFFUL).toByte()
            num = num shr 8
        }
        
        return result
    }
}
