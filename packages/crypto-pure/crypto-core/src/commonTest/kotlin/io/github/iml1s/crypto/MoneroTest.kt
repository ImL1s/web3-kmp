package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class MoneroTest {

    /**
     * Test Vector 1: Monero mainnet standard address
     * 
     * Using generated Ed25519 keys to create a standard address.
     */
    @Test
    fun testMainnetStandardAddress() {
        // Generate deterministic Ed25519 keys for testing
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        
        val address = Monero.getAddress(spendKey, viewKey, network = "mainnet")
        
        // Verify it starts with '4'
        assertTrue(address.startsWith("4"), "Monero mainnet standard should start with '4'")
        
        // Verify length (95 characters)
        assertEquals(95, address.length, "Standard address should be 95 characters")
        
        // Verify address is valid
        assertTrue(Monero.isValidAddress(address))
        
        // Verify it's not a subaddress
        assertFalse(Monero.isSubaddress(address))
        
        // Verify network
        assertEquals("mainnet", Monero.getNetwork(address))
    }

    /**
     * Test Vector 2: Monero testnet standard address
     */
    @Test
    fun testTestnetStandardAddress() {
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        
        val address = Monero.getAddress(spendKey, viewKey, network = "testnet")
        
        // Verify it starts with '9'
        assertTrue(address.startsWith("9"), "Monero testnet standard should start with '9'")
        
        // Verify length (95 characters)
        assertEquals(95, address.length)
        
        // Verify address is valid
        assertTrue(Monero.isValidAddress(address))
        
        // Verify network
        assertEquals("testnet", Monero.getNetwork(address))
    }

    /**
     * Test Vector 3: Monero subaddress
     */
    @Test
    fun testSubaddress() {
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        
        val address = Monero.getSubaddress(spendKey, viewKey, network = "mainnet")
        
        // Verify it starts with '8'
        assertTrue(address.startsWith("8"), "Monero mainnet subaddress should start with '8'")
        
        // Verify length (95 characters)
        assertEquals(95, address.length)
        
        // Verify address is valid
        assertTrue(Monero.isValidAddress(address))
        
        // Verify it's a subaddress
        assertTrue(Monero.isSubaddress(address))
    }

    /**
     * Test Vector 4: Monero integrated address
     */
    @Test
    fun testIntegratedAddress() {
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        val paymentId = ByteArray(8) { (it + 100).toByte() }
        
        val address = Monero.getIntegratedAddress(spendKey, viewKey, paymentId, network = "mainnet")
        
        // Verify it starts with '4'
        assertTrue(address.startsWith("4"), "Monero mainnet integrated should start with '4'")
        
        // Verify length (106 characters for integrated)
        assertEquals(106, address.length, "Integrated address should be 106 characters")
        
        // Verify address is valid
        assertTrue(Monero.isValidAddress(address))
        
        // Verify it's an integrated address
        assertTrue(Monero.isIntegratedAddress(address))
    }

    /**
     * Test address decode
     */
    @Test
    fun testDecodeAddress() {
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        
        val address = Monero.getAddress(spendKey, viewKey, network = "mainnet")
        val (networkByte, decodedSpend, decodedView) = Monero.decodeAddress(address)
        
        assertEquals(Monero.MAINNET_STANDARD, networkByte)
        assertTrue(spendKey.contentEquals(decodedSpend))
        assertTrue(viewKey.contentEquals(decodedView))
    }

    /**
     * Test validation with various inputs
     */
    @Test
    fun testValidation() {
        // Generate a valid address
        val spendKey = ByteArray(32) { it.toByte() }
        val viewKey = ByteArray(32) { (it + 32).toByte() }
        val validAddress = Monero.getAddress(spendKey, viewKey)
        assertTrue(Monero.isValidAddress(validAddress))
        
        // Invalid: wrong prefix
        assertFalse(Monero.isValidAddress("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))
        
        // Invalid: empty string
        assertFalse(Monero.isValidAddress(""))
        
        // Invalid: too short
        assertFalse(Monero.isValidAddress("4xxx"))
        
        // Invalid: corrupted checksum
        if (validAddress.isNotEmpty()) {
            val lastChar = validAddress.last()
            val newLastChar = if (lastChar == 'a') 'b' else 'a'
            val invalidChecksum = validAddress.dropLast(1) + newLastChar
            assertFalse(Monero.isValidAddress(invalidChecksum))
        }
    }

    /**
     * Test Monero Base58 encoding/decoding
     */
    @Test
    fun testMoneroBase58() {
        // Test round-trip
        val original = ByteArray(32) { it.toByte() }
        val encoded = MoneroBase58.encode(original)
        val decoded = MoneroBase58.decode(encoded)
        
        assertTrue(original.contentEquals(decoded), "Round-trip encoding should preserve data")
        
        // Test empty
        assertEquals("", MoneroBase58.encode(ByteArray(0)))
        assertEquals(0, MoneroBase58.decode("").size)
    }

    /**
     * Test derivation path
     */
    @Test
    fun testDerivationPath() {
        // Monero uses coin_type = 128
        assertEquals("m/44'/128'/0'/0/0", Monero.getDerivationPath())
        assertEquals("m/44'/128'/1'/0/5", Monero.getDerivationPath(account = 1, index = 5))
    }

    /**
     * Official Monero Base58 Block Tests
     * Source: monero/tests/unit_tests/base58.cpp
     */
    @Test
    fun testOfficialBase58Blocks() {
        assertEquals("11", MoneroBase58.encode(byteArrayOf(0x00.toByte())))
        assertEquals("1z", MoneroBase58.encode(byteArrayOf(0x39.toByte())))
        assertEquals("5Q", MoneroBase58.encode(byteArrayOf(0xFF.toByte())))
        
        assertEquals("111", MoneroBase58.encode(byteArrayOf(0x00, 0x00)))
        assertEquals("11z", MoneroBase58.encode(byteArrayOf(0x00, 0x39)))
        assertEquals("15R", MoneroBase58.encode(byteArrayOf(0x01, 0x00)))
        assertEquals("LUv", MoneroBase58.encode(byteArrayOf(0xFF.toByte(), 0xFF.toByte())))
        
        assertEquals("11111", MoneroBase58.encode(byteArrayOf(0, 0, 0)))
        assertEquals("2UzHL", MoneroBase58.encode(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())))
        
        assertEquals("jpXCZedGfVQ", MoneroBase58.encode(ByteArray(8) { 0xFF.toByte() }))
        assertEquals("11111111111", MoneroBase58.encode(ByteArray(8) { 0 }))
    }

    /**
     * Official Monero Testnet Address Vector
     * Source: User search result / Monero docs
     */
    @Test
    fun testOfficialTestnetVector() {
        // Spend key (private): ab2210d06d5cef6274a66ce9ed39c8c19e467915e73a9d37e939f6ce18f8c905
        // View key (private): 52aa4c69b93b780885c9d7f51e6fd5795904962c61a2e07437e130784846f70d
        // Ed25519 public key derivation is needed here if we start from private keys.
        // For now, I'll use the final address to check validAddress and length.
        val expectedAddress = "9wDZ4yA7aqiNQfnFrKsKQPM4jHyYRcdHdP5d5FDGa12YDs7QBFPwXgyZuk9WnCfAdvAKRWk4psFsYXb55xYGHgxmF6cxpUj"
        
        assertTrue(Monero.isValidAddress(expectedAddress))
        assertEquals("testnet", Monero.getNetwork(expectedAddress))
        assertFalse(Monero.isIntegratedAddress(expectedAddress))
    }

    @Test
    fun testEdgeCases() {
        // Invalid Length (Standard address should be 95 chars)
        val validAddress = "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXzksdewwPwc54iFwHVasXTDvA8M95qKgQB54hLessXNwCPwZQJA"
        assertFalse(Monero.isValidAddress(validAddress.substring(0, 94)))
        assertFalse(Monero.isValidAddress(validAddress + "A"))

        // Invalid Prefix (Starts with 'A' instead of '4' for mainnet or '8','9' etc.)
        assertFalse(Monero.isValidAddress("A" + validAddress.substring(1)))

        // Invalid Characters (Non-Base58 characters '0', 'O', 'I', 'l')
        // Replace last char 'A' with '0'
        val invalidCharAddress = validAddress.dropLast(1) + "0"
        assertFalse(Monero.isValidAddress(invalidCharAddress))

        // Checksum Failure
        // Change last character to something valid in Base58 but invalid checksum
        val invalidChecksumAddress = validAddress.dropLast(1) + "B" 
        assertFalse(Monero.isValidAddress(invalidChecksumAddress))
        
        // Empty String
        assertFalse(Monero.isValidAddress(""))
        
        // Integrated Address Edge Case
        // Valid integrated address
        val validIntegrated = "4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK"
        assertTrue(Monero.isValidAddress(validIntegrated))
        assertTrue(Monero.isIntegratedAddress(validIntegrated))
        
        // Invalid Integrated Address Length (should be 106)
        assertFalse(Monero.isValidAddress(validIntegrated.substring(0, 105)))
    }
}
