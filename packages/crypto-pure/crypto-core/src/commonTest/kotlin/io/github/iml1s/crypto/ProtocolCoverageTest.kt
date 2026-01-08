package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class ProtocolCoverageTest {

    @Test
    fun testSolana() {
        // Test Key Generation
        val keyPair = Solana.generateKeyPair()
        assertEquals(32, keyPair.privateKey.size)
        assertEquals(32, keyPair.publicKey.size)

        val addr = Solana.getAddress(keyPair.publicKey)
        assertTrue(addr.isNotEmpty())
        // Base58 of 32 bytes is typically 43-44 chars.
        assertTrue(addr.length >= 32 && addr.length <= 44, "Solana address length was ${addr.length}, address: $addr")
    }

    
    @Test
    fun testTron() {
        // Official Tron Test Vector (Hex to Base58Check)
        // This vector is verified by independent Base58Check logic.
        val hexAddr = "418840E6C55B9ADA326D211D818C34A994AECED808"
        val expectedBase58 = "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL"
        
        val bytes = Hex.decode(hexAddr)
        val actualBase58 = Base58.encodeWithChecksum(bytes)
        assertEquals(expectedBase58, actualBase58)
    }




    
    @Test
    fun testSegwitAddress() {
        // Derive a key and get Bech32 address
        val seed = Hex.decode("000102030405060708090a0b0c0d0e0f")
        val hd = HDWallet()
        val master = hd.generateMasterKey(seed)
        val segwitAddr = hd.getSegwitAddress(master)
        assertTrue(segwitAddr.startsWith("bc1q"), "Segwit address should start with bc1q, got $segwitAddr")
    }

}
