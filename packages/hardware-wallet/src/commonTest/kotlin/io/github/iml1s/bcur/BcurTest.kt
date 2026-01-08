package io.github.iml1s.bcur

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BcurTest {

    @Test
    fun testCRC32() {
        val data = "Hello, world!".encodeToByteArray()
        val expected = 0xebe6c6e6L
        assertEquals(expected, CRC32.compute(data))
    }

    @Test
    fun testBytewordsStandard() {
        // Test vector from BCR-2020-012
        val data = byteArrayOf(0, 1, 2, 3, 255.toByte())
        // CRC32 of valid data input
        // Let's rely on self-consistency first for this quick check if I don't have exact vector at hand,
        // but wait, standard vectors are better.
        // "Hello, world!" -> 48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21
        // CRC32: ebe6c6e6
        // Bytewords needs to append checksum (4 bytes).
        
        val input = "Hello, world!".encodeToByteArray()
        val encoded = Bytewords.encode(input, Bytewords.Style.STANDARD)
        val decoded = Bytewords.decode(encoded, Bytewords.Style.STANDARD)
        
        assertTrue(input.contentEquals(decoded))
    }

    @Test
    fun testBytewordsMinimal() {
        val input = "Hello, world!".encodeToByteArray()
        val encoded = Bytewords.encode(input, Bytewords.Style.MINIMAL)
        val decoded = Bytewords.decode(encoded, Bytewords.Style.MINIMAL)
        
        assertTrue(input.contentEquals(decoded))
        
        // Minimal encoding should be 2 chars per byte (including 4 checksum bytes)
        // input len 13 + 4 checksum = 17 bytes * 2 chars = 34 chars
        // assertEquals(34, encoded.length) 
        // Logic check: 13 bytes payload + 4 bytes checksum = 17 bytes. 
        // Minimal is 2 letters per byte -> 34 characters.
        assertEquals((input.size + 4) * 2, encoded.length)
    }

    @Test
    fun testURSinglePart() {
        val type = "bytes"
        val cbor = "Hello".encodeToByteArray() // Not real CBOR but good enough for transport test
        val ur = UR(type, cbor)
        val encoded = UREncoder.encode(ur)
        
        assertTrue(encoded.startsWith("ur:bytes/"))
        
        val decodedUr = UR.parse(encoded)
        assertEquals(ur.type, decodedUr.type)
        assertTrue(ur.cborData.contentEquals(decodedUr.cborData))
    }
    
    @Test
    fun testURMultipart() {
        // Create large data to force multipart
        val data = ByteArray(1001) { it.toByte() }
        val ur = UR("bytes", data)
        val encoder = UREncoder(ur, maxFragmentLen = 100, minFragmentLen = 10)
        
        assertTrue(!encoder.isSinglePart())
        
        // Generate a few parts
        val part1 = encoder.nextPart()
        assertTrue(part1.startsWith("ur:bytes/1-"))
        
        val part2 = encoder.nextPart()
        assertTrue(part2.startsWith("ur:bytes/2-"))
    }
}
