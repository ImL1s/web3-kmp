package io.github.iml1s.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

/**
 * Ristretto255 implementation following RFC 9496
 * https://datatracker.ietf.org/doc/html/rfc9496
 */
class Ristretto255(
    val x: BigInteger,
    val y: BigInteger,
    val z: BigInteger,
    val t: BigInteger
) {
    companion object {
        // p = 2^255 - 19
        private val P = BigInteger.ONE.shl(255).subtract(BigInteger.fromInt(19))
        
        // d = -121665/121666
        private val D_NUM = BigInteger.fromInt(121665).negate()
        private val D_DEN = BigInteger.fromInt(121666)
        val D = D_NUM.mod(P).multiply(D_DEN.modInverse(P)).mod(P)
        
        // sqrt(-1) mod p
        val SQRT_M1 = BigInteger.parseString("19681161376707505956807079304988542015446066515923890162744021073123829784752")
        
        // INVSQRT_A_MINUS_D = 1/sqrt(a-d) where a=-1
        val INVSQRT_A_MINUS_D = BigInteger.parseString("54469307008909316920995813868745141605393597292927456921205312896311721017578")
        
        // Base point (generator) - standard Ristretto255 basepoint
        val BASEPOINT: Ristretto255
        
        init {
            // Standard basepoint from RFC 9496
            val basepointHex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
            val bytes = hexToBytes(basepointHex)
            BASEPOINT = fromBytes(bytes) ?: throw RuntimeException("Failed to decode standard BASEPOINT")
        }
        
        /**
         * Decode a 32-byte string into a Ristretto255 group element
         * RFC 9496 Section 4.3.1
         */
        fun fromBytes(bytes: ByteArray): Ristretto255? {
            if (bytes.size != 32) return null
            
            // 1. Interpret as unsigned integer s in little-endian
            val s = BigInteger.fromByteArray(bytes.reversedArray(), Sign.POSITIVE)
            if (s >= P) return null
            
            // 2. Check if s is negative (odd)
            if (isNegative(s)) return null
            
            // 3. Process s
            val ss = s.multiply(s).mod(P)
            val u1 = BigInteger.ONE.subtract(ss).mod(P)
            val u2 = BigInteger.ONE.add(ss).mod(P)
            val u2_sqr = u2.multiply(u2).mod(P)
            
            // v = -(D * u1^2) - u2_sqr
            val u1_sqr = u1.multiply(u1).mod(P)
            val v = D.multiply(u1_sqr).negate().subtract(u2_sqr).mod(P)
            
            // (was_square, invsqrt) = SQRT_RATIO_M1(1, v * u2_sqr)
            val (wasSquare, invsqrt) = sqrtRatioM1(BigInteger.ONE, v.multiply(u2_sqr).mod(P))
            
            val den_x = invsqrt.multiply(u2).mod(P)
            val den_y = invsqrt.multiply(den_x).multiply(v).mod(P)
            
            var x = s.add(s).multiply(den_x).mod(P) // 2*s*den_x
            x = ctAbs(x)
            
            val y = u1.multiply(den_y).mod(P)
            val t = x.multiply(y).mod(P)
            
            // 4. Validation
            if (!wasSquare) return null
            if (isNegative(t)) return null
            if (y == BigInteger.ZERO) return null
            
            return Ristretto255(x, y, BigInteger.ONE, t)
        }
        
        /**
         * SQRT_RATIO_M1(u, v) - RFC 9496 Section 4.2
         * Returns (was_square, result)
         */
        private fun sqrtRatioM1(u: BigInteger, v: BigInteger): Pair<Boolean, BigInteger> {
            // r = (u * v^3) * (u * v^7)^((p-5)/8)
            val v2 = v.multiply(v).mod(P)
            val v3 = v2.multiply(v).mod(P)
            val v7 = v3.multiply(v2).multiply(v2).mod(P)
            
            val uv7 = u.multiply(v7).mod(P)
            val exp = P.subtract(BigInteger.fromInt(5)).divide(BigInteger.fromInt(8))
            val pow = modPow(uv7, exp, P)
            
            var r = u.multiply(v3).multiply(pow).mod(P)
            
            // check = v * r^2
            val check = v.multiply(r).multiply(r).mod(P)
            
            val correctSignSqrt = ctEq(check, u)
            val flippedSignSqrt = ctEq(check, u.negate().mod(P))
            val flippedSignSqrtI = ctEq(check, u.negate().multiply(SQRT_M1).mod(P))
            
            val rPrime = SQRT_M1.multiply(r).mod(P)
            r = ctSelect(rPrime, r, flippedSignSqrt || flippedSignSqrtI)
            
            // Choose nonnegative square root
            r = ctAbs(r)
            
            val wasSquare = correctSignSqrt || flippedSignSqrt
            
            return Pair(wasSquare, r)
        }
        
        /**
         * IS_NEGATIVE(x) - returns true if x is odd
         */
        private fun isNegative(x: BigInteger): Boolean {
            return x.and(BigInteger.ONE) == BigInteger.ONE
        }
        
        /**
         * CT_ABS(x) - returns nonnegative representative
         */
        private fun ctAbs(x: BigInteger): BigInteger {
            return if (isNegative(x)) P.subtract(x) else x
        }
        
        /**
         * CT_EQ(a, b) - constant-time equality
         */
        private fun ctEq(a: BigInteger, b: BigInteger): Boolean {
            return a.mod(P) == b.mod(P)
        }
        
        /**
         * CT_SELECT(a, b, condition) - select a if condition else b
         */
        private fun ctSelect(a: BigInteger, b: BigInteger, condition: Boolean): BigInteger {
            return if (condition) a else b
        }
        
        private fun modPow(base: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger {
            var res = BigInteger.ONE
            var b = base.mod(modulus)
            var e = exponent
            
            while (e > BigInteger.ZERO) {
                if (e.and(BigInteger.ONE) == BigInteger.ONE) {
                    res = res.multiply(b).mod(modulus)
                }
                b = b.multiply(b).mod(modulus)
                e = e.shr(1)
            }
            return res
        }
        
        private fun hexToBytes(s: String): ByteArray {
            val len = s.length
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                data[i / 2] = ((hexDigitToInt(s[i]) shl 4) + hexDigitToInt(s[i + 1])).toByte()
                i += 2
            }
            return data
        }

        private fun hexDigitToInt(c: Char): Int {
            return when (c) {
                in '0'..'9' -> c - '0'
                in 'a'..'f' -> c - 'a' + 10
                in 'A'..'F' -> c - 'A' + 10
                else -> throw IllegalArgumentException("Invalid hex character: $c")
            }
        }
    }
    
    /**
     * Encode a Ristretto255 group element to 32 bytes
     * RFC 9496 Section 4.3.2
     */
    fun toBytes(): ByteArray {
        val u1 = (z.add(y)).multiply(z.subtract(y)).mod(P)
        val u2 = x.multiply(y).mod(P)
        
        // (_, invsqrt) = SQRT_RATIO_M1(1, u1 * u2^2)
        val u2_sqr = u2.multiply(u2).mod(P)
        val (_, invsqrt) = sqrtRatioM1(BigInteger.ONE, u1.multiply(u2_sqr).mod(P))
        
        val den1 = invsqrt.multiply(u1).mod(P)
        val den2 = invsqrt.multiply(u2).mod(P)
        val z_inv = den1.multiply(den2).multiply(t).mod(P)
        
        val ix0 = x.multiply(SQRT_M1).mod(P)
        val iy0 = y.multiply(SQRT_M1).mod(P)
        val enchanted_denominator = den1.multiply(INVSQRT_A_MINUS_D).mod(P)
        
        val rotate = isNegative(t.multiply(z_inv).mod(P))
        
        var xFinal = ctSelect(iy0, x, rotate)
        var yFinal = ctSelect(ix0, y, rotate)
        val den_inv = ctSelect(enchanted_denominator, den2, rotate)
        
        yFinal = ctSelect(yFinal.negate().mod(P), yFinal, isNegative(xFinal.multiply(z_inv).mod(P)))
        
        var s = den_inv.multiply(z.subtract(yFinal)).mod(P)
        s = ctAbs(s)
        
        // Encode as 32-byte little-endian
        val bytes = s.toByteArray()
        val out = ByteArray(32)
        val rev = bytes.reversedArray()
        val len = minOf(rev.size, 32)
        for (i in 0 until len) {
            out[i] = rev[i]
        }
        return out
    }
    
    private fun minOf(a: Int, b: Int): Int {
        return if (a < b) a else b
    }

    /**
     * Point addition - delegate to Edwards addition
     */
    fun add(other: Ristretto255): Ristretto255 {
        // Extended twisted Edwards addition formula
        val A = y.subtract(x).multiply(other.y.subtract(other.x)).mod(P)
        val B = y.add(x).multiply(other.y.add(other.x)).mod(P)
        val C = t.multiply(BigInteger.TWO).multiply(D).multiply(other.t).mod(P)
        val D_ = z.multiply(BigInteger.TWO).multiply(other.z).mod(P)
        
        val E = B.subtract(A).mod(P)
        val F = D_.subtract(C).mod(P)
        val G = D_.add(C).mod(P)
        val H = B.add(A).mod(P)
        
        val x3 = E.multiply(F).mod(P)
        val y3 = G.multiply(H).mod(P)
        val t3 = E.multiply(H).mod(P)
        val z3 = F.multiply(G).mod(P)
        
        return Ristretto255(x3, y3, z3, t3)
    }
    
    fun subtract(other: Ristretto255): Ristretto255 {
        return this.add(other.negate())
    }
    
    fun negate(): Ristretto255 {
        return Ristretto255(x.negate().mod(P), y, z, t.negate().mod(P))
    }
    
    /**
     * Scalar multiplication using double-and-add
     */
    fun multiply(scalar: ByteArray): Ristretto255 {
        // Identity point
        var result = Ristretto255(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
        
        // Interpret scalar as little-endian unsigned integer
        val s = BigInteger.fromByteArray(scalar.reversedArray(), Sign.POSITIVE)
        
        var temp = this
        var k = s
        
        // Double-and-add for 256 bits
        for (i in 0 until 256) {
            if (k.and(BigInteger.ONE) == BigInteger.ONE) {
                result = result.add(temp)
            }
            temp = temp.add(temp) // Point doubling
            k = k.shr(1)
        }
        
        return result
    }
}
