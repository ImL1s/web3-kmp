package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class HmacTest {

    @Test
    fun testHmacSha256() {
        // RFC 4231 Vector 2
        val key = "Jefe".encodeToByteArray()
        val data = "what do ya want for nothing?".encodeToByteArray()
        val expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        
        val actual = HmacSha256.hmac(key, data).toHexString()
        assertEquals(expected, actual)
    }

    @Test
    fun testHmacSha512() {
        // RFC 4231 Vector 2
        val key = "Jefe".encodeToByteArray()
        val data = "what do ya want for nothing?".encodeToByteArray()
        // Correct RFC 4231 Vector 2 expected value for HMAC-SHA512
        val expected = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554" +
                       "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        
        val actual = HmacSha512.hmac(key, data).toHexString()
        assertEquals(expected.lowercase(), actual.lowercase())
    }

    private fun ByteArray.toHexString(): String = Hex.encode(this)
}

