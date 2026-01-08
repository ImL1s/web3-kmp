package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class DashTest {

    /**
     * Test Vector 1: Known Dash mainnet address
     * 
     * These test vectors are derived from the Dash protocol specification.
     * P2PKH addresses start with 'X' and use version byte 0x4C (76).
     */
    @Test
    fun testEdgeCases() {
        val validAddress = "XyHHinPZB5Q4FC9jtbksaQBJmXq48gtVGb"
        
        // Invalid Prefix/Version (Bitcoin '1')
        assertFalse(Dash.isValidAddress("1yHHinPZB5Q4FC9jtbksaQBJmXq48gtVGb"))
        
        // Invalid Length
        assertFalse(Dash.isValidAddress(validAddress.substring(0, 20)))
        
        // Invalid Checksum
        val invalidChecksum = validAddress.dropLast(1) + "a" // Assuming 'a' makes checksum invalid
        assertFalse(Dash.isValidAddress(invalidChecksum))
        
        // Empty
        assertFalse(Dash.isValidAddress(""))
        
        // Non-Base58
        assertFalse(Dash.isValidAddress(validAddress.replace('X', '0')))
    }

    @Test
    fun testOfficialMainnetP2PKHVector() {
        // Official Dash Test Vector
        // PubKey: 020d47568a5e517067a2836c3823fbc58169a7662bfae934a4d41da3e23c98d816
        // Address: XyHHinPZB5Q4FC9jtbksaQBJmXq48gtVGb
        val pubKeyHex = "020d47568a5e517067a2836c3823fbc58169a7662bfae934a4d41da3e23c98d816"
        val expectedAddress = "XyHHinPZB5Q4FC9jtbksaQBJmXq48gtVGb"
        
        val actualAddress = Dash.getAddress(Hex.decode(pubKeyHex), testnet = false)
        assertEquals(expectedAddress, actualAddress)
        assertTrue(Dash.isValidAddress(actualAddress))
    }

    @Test
    fun testMainnetP2PKHAddress() {
        // Test vector from Dash documentation
        // Using a known public key that produces a predictable address
        val pubKeyHex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        val pubKey = Hex.decode(pubKeyHex)
        
        val address = Dash.getAddress(pubKey, testnet = false)
        
        // Verify it starts with 'X'
        assertTrue(address.startsWith("X"), "Dash mainnet P2PKH should start with 'X'")
        
        // Verify address is valid
        assertTrue(Dash.isValidAddress(address))
        
        // Verify it's not testnet
        assertFalse(Dash.isTestnet(address))
    }

    /**
     * Test Vector 2: Testnet address
     */
    @Test
    fun testTestnetP2PKHAddress() {
        val pubKeyHex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        val pubKey = Hex.decode(pubKeyHex)
        
        val address = Dash.getAddress(pubKey, testnet = true)
        
        // Verify it starts with 'y'
        assertTrue(address.startsWith("y"), "Dash testnet P2PKH should start with 'y'")
        
        // Verify address is valid
        assertTrue(Dash.isValidAddress(address))
        
        // Verify it's testnet
        assertTrue(Dash.isTestnet(address))
    }

    /**
     * Test Vector 3: P2SH address (multisig)
     */
    @Test
    fun testP2SHAddress() {
        // A 20-byte script hash
        val scriptHash = ByteArray(20) { it.toByte() }
        
        val address = Dash.getP2SHAddress(scriptHash, testnet = false)
        
        // Verify it starts with '7'
        assertTrue(address.startsWith("7"), "Dash mainnet P2SH should start with '7'")
        
        // Verify address is valid
        assertTrue(Dash.isValidAddress(address))
    }

    /**
     * Test address validation with various inputs
     */
    @Test
    fun testValidation() {
        // Valid mainnet P2PKH
        val pubKey = Hex.decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        val validAddress = Dash.getAddress(pubKey)
        assertTrue(Dash.isValidAddress(validAddress))
        
        // Invalid: wrong prefix (Bitcoin address)
        assertFalse(Dash.isValidAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
        
        // Invalid: empty string
        assertFalse(Dash.isValidAddress(""))
        
        // Invalid: too short
        assertFalse(Dash.isValidAddress("X"))
        
        // Invalid: corrupted checksum
        if (validAddress.isNotEmpty()) {
            val lastChar = validAddress.last()
            val newLastChar = if (lastChar == 'a') 'b' else 'a'
            val invalidChecksum = validAddress.dropLast(1) + newLastChar
            assertFalse(Dash.isValidAddress(invalidChecksum))
        }
    }

    /**
     * Test derivation path
     */
    @Test
    fun testDerivationPath() {
        assertEquals("m/44'/5'/0'/0/0", Dash.getDerivationPath())
        assertEquals("m/44'/5'/1'/0/5", Dash.getDerivationPath(account = 1, index = 5))
    }

    /**
     * Test uncompressed public key support
     */
    @Test
    fun testUncompressedPublicKey() {
        // 65-byte uncompressed public key (0x04 prefix)
        val uncompressedPubKeyHex = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        val pubKey = Hex.decode(uncompressedPubKeyHex)
        
        val address = Dash.getAddress(pubKey)
        
        assertTrue(address.startsWith("X"))
        assertTrue(Dash.isValidAddress(address))
    }
}
