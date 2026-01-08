package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolkadotTest {

    // Alice Public Key (Standard Substrate Test Vector)
    // Hex: d43593c715fdd31c61141abd04a99fd6822c8558854    // Public Key matching the addresses 15oF... and 5Grw...
    // Note: The classic "d4...da0e" key is often cited, but the addresses below actually encode "d4...da27d"
    private val ALICE_PUBKEY_HEX = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
    
    // Expected Addresses
    // Polkadot (Net 0): 15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5
    // Substrate (Net 42): 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
    // Kusama (Net 2): D945.... (Let's check authoritative source if needed, stick to 0/42 for now)

    @Test
    fun testAlicePolkadotAddress() {
        val pubKey = Hex.decode(ALICE_PUBKEY_HEX)
        val expected = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
        
        val actual = Polkadot.getAddress(pubKey, networkId = 0)
        assertEquals(expected, actual)
    }

    @Test
    fun testAliceSubstrateAddress() {
        val pubKey = Hex.decode(ALICE_PUBKEY_HEX)
        val expected = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        
        val actual = Polkadot.getAddress(pubKey, networkId = 42)
        assertEquals(expected, actual)
    }

    @Test
    fun testDecode() {
        val address = "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"
        val (net, pubKey) = SS58.decode(address)
        
        assertEquals(0, net)
        assertEquals(ALICE_PUBKEY_HEX, Hex.encode(pubKey))
    }
}
