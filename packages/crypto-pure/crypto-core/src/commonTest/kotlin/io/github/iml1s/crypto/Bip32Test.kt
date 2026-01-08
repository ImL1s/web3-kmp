package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * BIP32 基本功能測試
 */
class Bip32Test {

    @Test
    fun testMasterKeyFromSeed() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        val master = Bip32.masterKeyFromSeed(seed)
        
        // Verify master key properties
        assertEquals(0, master.depth)
        assertEquals(0, master.childNumber)
        assertEquals(32, master.chainCode.size)
        assertEquals(32, master.privateKey.size)
    }


    @Test
    fun testDeriveChild() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        val master = Bip32.masterKeyFromSeed(seed)
        
        // Derive m/0 (non-hardened)
        val m0 = Bip32.deriveChild(master, 0, false)
        assertEquals(1, m0.depth)
        assertEquals(0, m0.childNumber)
        
        // Derive m/0' (hardened)
        val m0h = Bip32.deriveChild(master, 0, true)
        assertEquals(1, m0h.depth)
        assertTrue(m0h.childNumber.toUInt() >= 0x80000000u) // Hardened bit set
    }

    @Test
    fun testDerivePath() {
        val seed = "000102030405060708090a0b0c0d0e0f".hexToByteArray()
        
        // m/44'/60'/0'/0/0 (Ethereum path)
        val ethKey = Bip32.derivePath(seed, "m/44'/60'/0'/0/0")
        assertEquals(5, ethKey.depth)
    }

    private fun String.hexToByteArray(): ByteArray = Hex.decode(this)
}

