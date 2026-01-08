package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertContentEquals
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

class Sr25519DebugTest {

    @Test
    fun testRistrettoEncodingRoundtrip() {
        val B = Ristretto255.BASEPOINT
        val bytes = B.toBytes()
        assertEquals(32, bytes.size)
        
        val B_decoded = Ristretto255.fromBytes(bytes)
        assertNotNull(B_decoded, "Failed to decode basepoint")
        
        val bytes2 = B_decoded.toBytes()
        
        println("B bytes: ${bytes.joinToString(",") { it.toString() }}")
        println("B2 bytes: ${bytes2.joinToString(",") { it.toString() }}")
        
        assertTrue(bytes.contentEquals(bytes2), "Roundtrip encoding failed")
    }
    
    @Test
    fun testPointAddition() {
        val B = Ristretto255.BASEPOINT
        val P2 = B.add(B) // 2B
        
        // Multiply by 2 scalar
        // Little endian 2
        val twoBytes = ByteArray(32)
        twoBytes[0] = 2
        val P2_mul = B.multiply(twoBytes)
        
        val p2Bytes = P2.toBytes()
        val p2MulBytes = P2_mul.toBytes()
        
        println("P+P bytes: ${p2Bytes.joinToString()}")
        println("P*2 bytes: ${p2MulBytes.joinToString()}")
        
        assertTrue(p2Bytes.contentEquals(p2MulBytes), "Add(P,P) != Mul(P,2)")
    }
    
    @Test
    fun testBasepointOnCurve() {
        val B = Ristretto255.BASEPOINT
        val L = Sr25519.L
        
        // B * L should be Identity (0 point in Ristretto)
        val identity = B.multiply(toBytes32(L))
        val idBytes = identity.toBytes()
        
        println("L * B bytes: ${idBytes.joinToString()}")
        
        val expected = ByteArray(32) // all zeros
        
        assertTrue(idBytes.contentEquals(expected), "Basepoint * Order should be Identity")
    }
    
    @Test
    fun testConstants() {
        // P = 2^255 - 19
        val P = BigInteger.ONE.shl(255).subtract(BigInteger.fromInt(19))
        
        val i = Ristretto255.SQRT_M1
        val i2 = i.multiply(i).mod(P)
        val minus1 = P.subtract(BigInteger.ONE)
        
        assertEquals(minus1, i2, "SQRT_M1 squared should be -1")
    }

    @Test
    fun testSchnorrEquation() {
        val B = Ristretto255.BASEPOINT
        val L = Sr25519.L
        
        val rVal = BigInteger.fromLong(12345).multiply(BigInteger.fromLong(1000000))
        val xVal = BigInteger.fromLong(67890).multiply(BigInteger.fromLong(1000000))
        val kVal = BigInteger.fromLong(11111).multiply(BigInteger.fromLong(1000000))
        
        val kx = kVal.multiply(xVal)
        val sVal = rVal.add(kx) 
        
        val sB = B.multiply(toBytes32(sVal))
        val R = B.multiply(toBytes32(rVal))
        val Pk = B.multiply(toBytes32(xVal))
        val kPk = Pk.multiply(toBytes32(kVal))
        val RHS = R.add(kPk)
        
        println("sB: ${sB.toBytes().joinToString()}")
        println("RHS: ${RHS.toBytes().joinToString()}")
        
        assertTrue(sB.toBytes().contentEquals(RHS.toBytes()), "s*B != R + k*Pk")
    }
    
    private fun toBytes32(i: BigInteger): ByteArray {
        val b = i.toByteArray()
        val out = ByteArray(32)
        val rev = b.reversedArray()
        val len = minOf(rev.size, 32)
        for (j in 0 until len) {
            out[j] = rev[j]
        }
        return out
    }
}
