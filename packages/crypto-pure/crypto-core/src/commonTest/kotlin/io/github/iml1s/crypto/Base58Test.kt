package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertContentEquals

class Base58Test {

    @Test
    fun testEncoding() {
        // Test simple encoding
        val input = byteArrayOf(0x00, 0x01, 0x09, 0x66, 0x77)
        val encoded = Base58.encode(input)
        assertTrue(encoded.isNotEmpty())
    }

    @Test
    fun testDecoding() {
        // Base58 decode of "2g"
        val decoded = Base58.decode("2g")
        assertContentEquals(byteArrayOf(0x61.toByte()), decoded)
    }

    @Test
    fun testRoundTrip() {
        val original = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val encoded = Base58.encode(original)
        val decoded = Base58.decode(encoded)
        assertContentEquals(original, decoded)
    }

    @Test
    fun testBase58WithChecksum() {
        // Test encodeWithChecksum
        val data = byteArrayOf(0x00, 0x01, 0x02, 0x03)
        val encoded = Base58.encodeWithChecksum(data)
        assertTrue(encoded.isNotEmpty())
        assertTrue(encoded.length > Base58.encode(data).length) // Should be longer due to checksum
    }
    
    @Test
    fun testEmpty() {
        val empty = byteArrayOf()
        val encoded = Base58.encode(empty)
        assertEquals("", encoded)
        assertContentEquals(empty, Base58.decode(""))
    }
}

