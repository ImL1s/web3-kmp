package io.github.iml1s.bcur.fountain

import io.github.iml1s.bcur.SHA256

/**
 * Xoshiro256** PRNG implementation for Fountain Code.
 * 
 * This deterministic RNG is required for Fountain Code to ensure
 * encoder and decoder use the same random sequence.
 * 
 * Based on: http://xoshiro.di.unimi.it/xoshiro256starstar.c
 * Public domain implementation.
 * 
 * Ported from https://github.com/sparrowwallet/hummingbird
 */
class Xoshiro256StarStar {
    private var s0: Long = 0
    private var s1: Long = 0
    private var s2: Long = 0
    private var s3: Long = 0
    
    constructor(seed: Long) {
        setSeed(seed)
    }
    
    constructor(seed: ByteArray) {
        val digestBytes = SHA256.hash(seed)
        val s = LongArray(4)
        
        for (i in 0 until 4) {
            val offset = i * 8
            var v = 0L
            for (n in 0 until 8) {
                v = v shl 8
                v = v or (digestBytes[offset + n].toLong() and 0xFF)
            }
            s[i] = v
        }
        
        setState(s[0], s[1], s[2], s[3])
    }
    
    fun setSeed(seed: Long) {
        var sms = splitmix64_1(seed)
        s0 = splitmix64_2(sms)
        sms = splitmix64_1(sms)
        s1 = splitmix64_2(sms)
        sms = splitmix64_1(sms)
        s2 = splitmix64_2(sms)
        sms = splitmix64_1(sms)
        s3 = splitmix64_2(sms)
    }
    
    fun setState(s0: Long, s1: Long, s2: Long, s3: Long) {
        require(!(s0 == 0L && s1 == 0L && s2 == 0L && s3 == 0L)) {
            "xoshiro256** state cannot be all zeroes"
        }
        this.s0 = s0
        this.s1 = s1
        this.s2 = s2
        this.s3 = s3
    }
    
    fun nextLong(): Long {
        val result = rotl(s1 * 5, 7) * 9
        
        val t = s1 shl 17
        
        s2 = s2 xor s0
        s3 = s3 xor s1
        s1 = s1 xor s2
        s0 = s0 xor s3
        
        s2 = s2 xor t
        
        s3 = rotl(s3, 45)
        
        return result
    }
    
    fun nextLong(bound: Long): Long {
        require(bound > 0) { "bound must be positive" }
        return (nextLong() and Long.MAX_VALUE) % bound
    }
    
    fun nextInt(): Int = nextLong().toInt()
    
    fun nextInt(bound: Int): Int = nextLong(bound.toLong()).toInt()
    
    fun nextDouble(): Double {
        return (nextLong() ushr 11) * 1.1102230246251565e-16
    }
    
    fun nextInt(lowerBound: Int, count: Int): Int {
        val next = nextDouble()
        return (next * count).toInt() + lowerBound
    }
    
    companion object {
        private const val SPLITMIX1_MAGIC = -7046029254386353131L // 0x9E3779B97F4A7C15L
        
        private fun splitmix64_1(x: Long): Long {
            return x + SPLITMIX1_MAGIC
        }
        
        private fun splitmix64_2(z: Long): Long {
            var r = z
            r = (r xor (r shr 30)) * -4658895280553007687L // 0xBF58476D1CE4E5B9L
            r = (r xor (r shr 27)) * -7723592293110705685L // 0x94D049BB133111EBL
            return r xor (r shr 31)
        }
        
        private fun rotl(x: Long, k: Int): Long {
            return (x shl k) or (x ushr (64 - k))
        }
    }
}
