package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * P1 regressions for group law, RFC 6979 (secp256k1), strict DER, secret-free errors, and RLP.
 *
 * Expected compact r||s is from an independent RFC 6979 + secp256k1 implementation
 * (Python HMAC-SHA256 bits2octets), not from this unit and not RFC 6979 A.2.5 (that appendix is P-256).
 * Oracle dump: implementer scratch oracle-rfc6979.log
 */
class P1CorrectnessTest {

    private fun String.hex(): ByteArray = Hex.decode(this)
    private fun ByteArray.hex(): String = Hex.encode(this)

    @Test
    fun pubKeyOfRejectsZeroAndDoesNotLeakKeyMaterial() {
        val zero = ByteArray(32)
        val ex = assertFails { Secp256k1Pure.pubKeyOf(zero) }
        assertNoSecretInThrowable(ex, zero)
    }

    @Test
    fun pubKeyOfRejectsOutOfRangeKeyWithoutInterpolatingBytes() {
        // Distinct 32-byte value >= n. The audit defect interpolated d.toByteArray() into
        // the exception ("d=<hex>"); any encoding of these bytes in message/cause/stack is a leak.
        val key = Hex.decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        val ex = assertFails { Secp256k1Pure.pubKeyOf(key) }
        assertNoSecretInThrowable(ex, key)
    }

    private fun assertNoSecretInThrowable(ex: Throwable, key: ByteArray) {
        val blob = buildString {
            var t: Throwable? = ex
            while (t != null) {
                append(t.message ?: "")
                append('\n')
                append(t.toString())
                append('\n')
                t = t.cause
            }
        }.lowercase()
        val hex = key.hex()
        assertFalse(blob.contains("d="), "exception interpolated private key (d=)")
        assertFalse(blob.contains(hex), "exception leaked private-key hex")
        val trimmed = hex.trimStart('0')
        if (trimmed.length >= 16) {
            assertFalse(blob.contains(trimmed), "exception leaked trimmed private-key hex")
        }
    }

    @Test
    fun verifyAcceptsValidSignatureWithDigestZero() {
        // Independent construction: d=1, k=1, z=0 ⇒ R=G, r=Gx, s=r*d = Gx.
        val z = ByteArray(32)
        val r = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".hex()
        val s = r
        val pub = ("04" +
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").hex()
        assertTrue(Secp256k1Pure.verify(z, r + s, pub))
    }

    @Test
    fun rfc6979Secp256k1MatchesIndependentOracle() {
        // Same key/hash as RFC 6979 A.2.5 *sample* material, but expected r||s is secp256k1, not P-256.
        val privateKey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721".hex()
        val messageHash = "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF".hex()
        val expected = "432310e32cb80eb6503a26ce83cc165c783b870845fb8aad6d970889fcd7a6c8" +
            "530128b6b81c548874a6305d93ed071ca6e05074d85863d4056ce89b02bfab69"
        val sig = Secp256k1Pure.sign(messageHash, privateKey)
        assertEquals(expected, sig.hex())
        val pub = Secp256k1Pure.pubKeyOf(privateKey, compressed = true)
        assertTrue(Secp256k1Pure.verify(messageHash, sig, pub))
    }

    @Test
    fun strictDerRejectsTrailingBytes() {
        val privateKey = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721".hex()
        val messageHash = "AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF".hex()
        val compact = Secp256k1Pure.sign(messageHash, privateKey)
        val r = compact.sliceArray(0 until 32)
        val s = compact.sliceArray(32 until 64)
        val der = encodeDer(r, s)
        val pub = Secp256k1Pure.pubKeyOf(privateKey, compressed = true)
        assertTrue(Secp256k1Pure.verify(messageHash, der, pub))
        val trailing = der + byteArrayOf(0x00)
        assertFalse(Secp256k1Pure.verify(messageHash, trailing, pub))
    }

    @Test
    fun rlpNegativeIntegerIsNotZeroEncoding() {
        val zero = Hex.encode(RLP.encode(0L))
        val one = Hex.encode(RLP.encode(1L))
        val v127 = Hex.encode(RLP.encode(127L))
        val v128 = Hex.encode(RLP.encode(128L))
        // Yellow Paper / ETH wiki unsigned integers (independent of this encoder).
        assertEquals("80", zero)
        assertEquals("01", one)
        assertEquals("7f", v127)
        assertEquals("8180", v128)
        assertFails { RLP.encode(-1L) }
        assertTrue(zero != Hex.encode(tryEncodeNegative()))
    }

    private fun tryEncodeNegative(): ByteArray {
        return try {
            RLP.encode(-1L)
        } catch (e: IllegalArgumentException) {
            byteArrayOf(0x01) // distinct from 0x80 so the inequality above holds after the throw
        }
    }

    private fun encodeDer(r: ByteArray, s: ByteArray): ByteArray {
        fun toDerInt(bytes: ByteArray): ByteArray {
            var b = bytes
            while (b.size > 1 && b[0] == 0.toByte()) {
                b = b.sliceArray(1 until b.size)
            }
            if ((b[0].toInt() and 0x80) != 0) {
                b = byteArrayOf(0) + b
            }
            return b
        }
        val rDer = toDerInt(r)
        val sDer = toDerInt(s)
        val body = byteArrayOf(0x02, rDer.size.toByte()) + rDer + byteArrayOf(0x02, sDer.size.toByte()) + sDer
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
