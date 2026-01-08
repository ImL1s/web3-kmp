package io.github.iml1s.crypto

/**
 * Pure Kotlin Implementation of SHA3-256 (FIPS 202)
 * 
 * Based on the Keccak sponge construction.
 * Note: SHA3-256 is different from Keccak-256 (used by Ethereum).
 * SHA3-256 uses domain separation suffix 0x06, Keccak-256 uses 0x01.
 */
object Sha3 {
    
    private const val RATE_256 = 1088 / 8  // 136 bytes for SHA3-256
    private const val CAPACITY_256 = 512 / 8  // 64 bytes
    
    // Keccak round constants
    private val RC = longArrayOf(
        0x0000000000000001UL.toLong(), 0x0000000000008082UL.toLong(),
        0x800000000000808aUL.toLong(), 0x8000000080008000UL.toLong(),
        0x000000000000808bUL.toLong(), 0x0000000080000001UL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008009UL.toLong(),
        0x000000000000008aUL.toLong(), 0x0000000000000088UL.toLong(),
        0x0000000080008009UL.toLong(), 0x000000008000000aUL.toLong(),
        0x000000008000808bUL.toLong(), 0x800000000000008bUL.toLong(),
        0x8000000000008089UL.toLong(), 0x8000000000008003UL.toLong(),
        0x8000000000008002UL.toLong(), 0x8000000000000080UL.toLong(),
        0x000000000000800aUL.toLong(), 0x800000008000000aUL.toLong(),
        0x8000000080008081UL.toLong(), 0x8000000000008080UL.toLong(),
        0x0000000080000001UL.toLong(), 0x8000000080008008UL.toLong()
    )
    
    // Rotation offsets
    private val ROTATION = arrayOf(
        intArrayOf(0, 36, 3, 41, 18),
        intArrayOf(1, 44, 10, 45, 2),
        intArrayOf(62, 6, 43, 15, 61),
        intArrayOf(28, 55, 25, 21, 56),
        intArrayOf(27, 20, 39, 8, 14)
    )
    
    /**
     * SHA3-256 hash function (FIPS 202)
     * Output: 32 bytes (256 bits)
     */
    fun sha3_256(data: ByteArray): ByteArray {
        return keccak(data, RATE_256, 32, 0x06)
    }
    
    /**
     * Keccak-256 hash function (Ethereum-style)
     * Output: 32 bytes (256 bits)
     */
    fun keccak256(data: ByteArray): ByteArray {
        return keccak(data, RATE_256, 32, 0x01)
    }
    
    private fun keccak(data: ByteArray, rate: Int, outputLen: Int, suffix: Int): ByteArray {
        val state = LongArray(25)
        
        // Absorb phase
        var offset = 0
        val block = ByteArray(rate)
        
        while (offset + rate <= data.size) {
            data.copyInto(block, 0, offset, offset + rate)
            xorBlock(state, block, rate)
            keccakF1600(state)
            offset += rate
        }
        
        // Pad and final block
        val remaining = data.size - offset
        data.copyInto(block, 0, offset, data.size)
        block.fill(0, remaining, rate)
        
        // SHA3 padding: suffix || 10*1
        block[remaining] = (block[remaining].toInt() xor suffix).toByte()
        block[rate - 1] = (block[rate - 1].toInt() xor 0x80).toByte()
        
        xorBlock(state, block, rate)
        keccakF1600(state)
        
        // Squeeze phase
        val output = ByteArray(outputLen)
        var outOffset = 0
        while (outOffset < outputLen) {
            val chunk = minOf(rate, outputLen - outOffset)
            for (i in 0 until chunk) {
                output[outOffset + i] = (state[i / 8] ushr (8 * (i % 8))).toByte()
            }
            outOffset += chunk
            if (outOffset < outputLen) {
                keccakF1600(state)
            }
        }
        
        return output
    }
    
    internal fun xorBlock(state: LongArray, block: ByteArray, rate: Int) {
        for (i in 0 until rate / 8) {
            state[i] = state[i] xor bytesToLong(block, i * 8)
        }
    }
    
    internal fun keccakF1600(state: LongArray) {
        val c = LongArray(5)
        val d = LongArray(5)
        val b = Array(5) { LongArray(5) }
        
        for (round in 0 until 24) {
            // θ step
            for (x in 0 until 5) {
                c[x] = state[x] xor state[x + 5] xor state[x + 10] xor state[x + 15] xor state[x + 20]
            }
            for (x in 0 until 5) {
                d[x] = c[(x + 4) % 5] xor rotl64(c[(x + 1) % 5], 1)
            }
            for (x in 0 until 5) {
                for (y in 0 until 5) {
                    state[x + 5 * y] = state[x + 5 * y] xor d[x]
                }
            }
            
            // ρ and π steps
            for (x in 0 until 5) {
                for (y in 0 until 5) {
                    b[y][(2 * x + 3 * y) % 5] = rotl64(state[x + 5 * y], ROTATION[x][y])
                }
            }
            
            // χ step
            for (x in 0 until 5) {
                for (y in 0 until 5) {
                    state[x + 5 * y] = b[x][y] xor ((b[(x + 1) % 5][y].inv()) and b[(x + 2) % 5][y])
                }
            }
            
            // ι step
            state[0] = state[0] xor RC[round]
        }
    }
    
    internal fun rotl64(x: Long, n: Int): Long {
        return (x shl n) or (x ushr (64 - n))
    }
    
    internal fun bytesToLong(b: ByteArray, off: Int): Long {
        return (b[off].toLong() and 0xffL) or
                ((b[off + 1].toLong() and 0xffL) shl 8) or
                ((b[off + 2].toLong() and 0xffL) shl 16) or
                ((b[off + 3].toLong() and 0xffL) shl 24) or
                ((b[off + 4].toLong() and 0xffL) shl 32) or
                ((b[off + 5].toLong() and 0xffL) shl 40) or
                ((b[off + 6].toLong() and 0xffL) shl 48) or
                ((b[off + 7].toLong() and 0xffL) shl 56)
    }
}
