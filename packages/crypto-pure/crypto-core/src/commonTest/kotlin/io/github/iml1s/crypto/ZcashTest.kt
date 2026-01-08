package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class ZcashTest {

    /**
     * Test Vector 1: Mainnet transparent P2PKH address (t1...)
     * Source: Zcash source code (src/test/key_tests.cpp)
     */
    @Test
    fun testEdgeCases() {
        val validAddress = "t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe"
        
        // Invalid Prefix
        assertFalse(Zcash.isValidAddress("z1" + validAddress.substring(2)))
        assertFalse(Zcash.isValidAddress("1" + validAddress.substring(1))) // Bitcoin prefix
        
        // Invalid Length
        assertFalse(Zcash.isValidAddress(validAddress.substring(0, 30)))
        
        // Invalid Checksum
        // Modify last character
        val invalidChecksum = validAddress.dropLast(1) + if (validAddress.last() == 'e') 'f' else 'e'
        assertFalse(Zcash.isValidAddress(invalidChecksum))
        
        // Empty
        assertFalse(Zcash.isValidAddress(""))
        
        // Non-Base58 chars
        assertFalse(Zcash.isValidAddress(validAddress.replace('e', '0'))) // 0 is invalid in Base58
    }

    @Test
    fun testOfficialMainnetVector() {
        // Official Zcash Test Vector
        // WIF (Uncompressed): 5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj
        // Address: t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe
        val wif = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj"
        val expectedAddress = "t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe"
        
        // 1. Decode WIF 
        // 5Hx... is uncompressed mainnet key (0x80 prefix)
        val decodedWif = Base58.decode(wif)
        // Format: [Version(1)] + [PrivKey(32)] + [Checksum(4)]
        // Size should be 37 for uncompressed
        assertEquals(37, decodedWif.size, "Uncompressed WIF should be 37 bytes")
        
        // 2. Extract Private Key
        val privateKey = decodedWif.copyOfRange(1, 33)
        
        // 3. Generate Public Key (Uncompressed per key_tests.cpp !key1.IsCompressed())
        val pubKey = Secp256k1Pure.generatePublicKey(privateKey, compressed = false)
        
        // 4. Generate Address
        val actualAddress = Zcash.getTransparentAddress(pubKey, testnet = false)
        
        assertEquals(expectedAddress, actualAddress)
        assertTrue(Zcash.isValidAddress(actualAddress))
        assertTrue(actualAddress.startsWith("t1"))
    }

    @Test
    fun testMainnetTransparentAddress() {
        // Use the secp256k1 generator point public key
        val pubKeyHex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        val pubKey = Hex.decode(pubKeyHex)
        
        val address = Zcash.getTransparentAddress(pubKey, testnet = false)
        
        // Verify it starts with 't1'
        assertTrue(address.startsWith("t1"), "Zcash mainnet P2PKH should start with 't1'")
        
        // Verify address is valid
        assertTrue(Zcash.isValidAddress(address))
        
        // Verify it's mainnet
        assertFalse(Zcash.isTestnet(address))
        
        // Verify it's P2PKH
        assertTrue(Zcash.isP2PKH(address))
    }

    /**
     * Test Vector 2: Testnet transparent address (tm...)
     */
    @Test
    fun testTestnetTransparentAddress() {
        val pubKeyHex = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        val pubKey = Hex.decode(pubKeyHex)
        
        val address = Zcash.getTransparentAddress(pubKey, testnet = true)
        
        // Verify it starts with 'tm'
        assertTrue(address.startsWith("tm"), "Zcash testnet P2PKH should start with 'tm'")
        
        // Verify address is valid
        assertTrue(Zcash.isValidAddress(address))
        
        // Verify it's testnet
        assertTrue(Zcash.isTestnet(address))
    }

    /**
     * Test Vector 3: P2SH address (t3...)
     */
    @Test
    fun testP2SHAddress() {
        val scriptHash = ByteArray(20) { it.toByte() }
        
        val address = Zcash.getP2SHAddress(scriptHash, testnet = false)
        
        // Verify it starts with 't3'
        assertTrue(address.startsWith("t3"), "Zcash mainnet P2SH should start with 't3'")
        
        // Verify address is valid
        assertTrue(Zcash.isValidAddress(address))
        
        // Verify it's not P2PKH
        assertFalse(Zcash.isP2PKH(address))
    }

    /**
     * Test address validation
     */
    @Test
    fun testValidation() {
        // Generate a valid address
        val pubKey = Hex.decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        val validAddress = Zcash.getTransparentAddress(pubKey)
        assertTrue(Zcash.isValidAddress(validAddress))
        
        // Invalid: wrong prefix (Bitcoin address)
        assertFalse(Zcash.isValidAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
        
        // Invalid: shielded address format (not supported)
        assertFalse(Zcash.isValidAddress("zs1z7rejlpsa98s2rrrfkwmaxu53e4ue0ulcrw0h4x5g8jl04tak0d3mm47vdtahatqrlkngh9sly"))
        
        // Invalid: empty string
        assertFalse(Zcash.isValidAddress(""))
        
        // Invalid: corrupted checksum
        if (validAddress.isNotEmpty()) {
            val lastChar = validAddress.last()
            val newLastChar = if (lastChar == 'a') 'b' else 'a'
            val invalidChecksum = validAddress.dropLast(1) + newLastChar
            assertFalse(Zcash.isValidAddress(invalidChecksum))
        }
    }

    /**
     * Test derivation path
     */
    @Test
    fun testDerivationPath() {
        // Zcash uses coin_type = 133
        assertEquals("m/44'/133'/0'/0/0", Zcash.getDerivationPath())
        assertEquals("m/44'/133'/2'/0/10", Zcash.getDerivationPath(account = 2, index = 10))
    }

    /**
     * Test uncompressed public key
     */
    @Test
    fun testUncompressedPublicKey() {
        val uncompressedPubKeyHex = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
            "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
        val pubKey = Hex.decode(uncompressedPubKeyHex)
        
        val address = Zcash.getTransparentAddress(pubKey)
        
        assertTrue(address.startsWith("t1"))
        assertTrue(Zcash.isValidAddress(address))
    }

    // ==========================================
    // Sapling Test Vectors
    // ==========================================

    @Test
    fun testSaplingAddressDecoding() {
        // Valid Zcash Sapling Address
        val address = "zs1cpf4prtmnqpg6x2ngcrwelu9a39z9l9lqukq9fwagnaqrknk34a7n3szwxpjuxfjdxkuzykel53"
        
        val (diversifier, pkd) = Zcash.decodeSaplingAddress(address)
        
        assertEquals(11, diversifier.size)
        assertEquals(32, pkd.size)
    }

    @Test
    fun testSaplingEdgeCases() {
        val validAddress = "zs1cpf4prtmnqpg6x2ngcrwelu9a39z9l9lqukq9fwagnaqrknk34a7n3szwxpjuxfjdxkuzykel53"
        
        // 1. Invalid HRP
        // Replace 'zs' with 'zt'
        val invalidHrp = "zt1cpf4prtmnqpg6x2ngcrwelu9a39z9l9lqukq9fwagnaqrknk34a7n3szwxpjuxfjdxkuzykel53"
        // Since Bech32 checksum depends on HRP, this will likely fail decoding or fail HRP check
        // If decoding succeeds (checksum matches by pure luck or if HRP isn't checked during decode), 
        // our explicit check should catch it.
        assertFailsWith<Exception> {
            Zcash.decodeSaplingAddress(invalidHrp)
        }

        // 2. Invalid Length (Payload)
        // A valid sapling address encodes 43 bytes (11 diversifier + 32 pkd)
        // If we modify bits to create a shorter/longer valid Bech32 string, 
        // the decodeSaplingAddress should still reject it due to length check (43 bytes).
        
        // We can simulate this by encoding garbage of wrong length
        val garbageShort = ByteArray(42) { 0 }
        val encodedShort = Bech32.encode("zs", Bech32.convertBits(garbageShort, 8, 5, true), Bech32.Spec.BECH32)
        assertFailsWith<IllegalArgumentException> {
            Zcash.decodeSaplingAddress(encodedShort)
        }
        
        // 3. Wrong Bech32 Variant (Sapling uses BECH32, not BECH32M)
        // Unified Addresses use BECH32M. Sapling must reject BECH32M encoded strings if strict.
        // However, our current Bech32.decode might return the Spec used.
        // Let's ensure our encode uses BECH32.
        val (div, pkd) = Zcash.decodeSaplingAddress(validAddress)
        val reEncoded = Zcash.encodeSaplingAddress(div, pkd)
        // Verify it didn't use 'm' variant if we were to check internals, 
        // but externally we verify equality with original.
        assertEquals(validAddress, reEncoded)
    }

    @Test
    fun testSaplingAddressRoundTrip() {
        val diversifier = ByteArray(11) { it.toByte() }
        val pkd = ByteArray(32) { (it + 50).toByte() }
        
        // Mainnet
        val mainnetAddr = Zcash.encodeSaplingAddress(diversifier, pkd, testnet = false)
        assertTrue(mainnetAddr.startsWith("zs1"))
        val (d1, p1) = Zcash.decodeSaplingAddress(mainnetAddr)
        assertTrue(diversifier.contentEquals(d1))
        assertTrue(pkd.contentEquals(p1))
        
        // Testnet
        val testnetAddr = Zcash.encodeSaplingAddress(diversifier, pkd, testnet = true)
        assertTrue(testnetAddr.startsWith("ztestsapling"))
        val (d2, p2) = Zcash.decodeSaplingAddress(testnetAddr)
        assertTrue(diversifier.contentEquals(d2))
        assertTrue(pkd.contentEquals(p2))
    }
}
