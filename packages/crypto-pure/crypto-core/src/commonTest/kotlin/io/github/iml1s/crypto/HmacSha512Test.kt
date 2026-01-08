package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class HmacSha512Test {

    @Test
    fun testRfc4231Vector1() {
        val key = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") // 20 bytes
        val data = "Hi There".encodeToByteArray()
        val expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        
        val actual = HmacSha512.hmac(key, data)
        assertEquals(expected, Hex.encode(actual), "HMAC-SHA512 RFC 4231 Vector 1 failed")
    }
}
