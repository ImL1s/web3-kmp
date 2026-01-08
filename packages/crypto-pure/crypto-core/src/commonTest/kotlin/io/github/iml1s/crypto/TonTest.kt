package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Comprehensive TON Tests
 * 
 * Test vectors sourced from official @ton/crypto library:
 * https://github.com/ton-org/ton-crypto/blob/master/src/mnemonic/mnemonic.spec.ts
 * 
 * Key derivation process:
 * 1. entropy = HMAC-SHA512(mnemonic.join(' '), password)
 * 2. seed = PBKDF2-SHA512(entropy, "TON default seed", 100000, 64)
 * 3. keyPair = Ed25519.fromSeed(seed[0:32])
 * 
 * The expected "key" in test vectors is 64-byte Ed25519 secretKey (seed + publicKey)
 */
class TonTest {

    // Official test vectors from @ton/crypto
    data class TestVector(
        val mnemonics: List<String>,
        val expectedSecretKeyHex: String // 64 bytes = 32 byte seed + 32 byte public key
    )

    private val officialTestVectors = listOf(
        // Vector #0
        TestVector(
            mnemonics = listOf(
                "hospital", "stove", "relief", "fringe", "tongue", "always", "charge", "angry", "urge",
                "sentence", "again", "match", "nerve", "inquiry", "senior", "coconut", "label", "tumble",
                "carry", "category", "beauty", "bean", "road", "solution"
            ),
            expectedSecretKeyHex = "9d659a6c2234db7f6e4f977e6e8653b9f5946d557163f31034011375d8f3f97df6c450a16bb1c514e22f1977e390a3025599aa1e7b00068a6aacf2119484c1bd"
        ),
        // Vector #1
        TestVector(
            mnemonics = listOf(
                "dose", "ice", "enrich",
                "trigger", "test", "dove",
                "century", "still", "betray",
                "gas", "diet", "dune",
                "use", "other", "base",
                "gym", "mad", "law",
                "immense", "village", "world",
                "example", "praise", "game"
            ),
            expectedSecretKeyHex = "119dcf2840a3d56521d260b2f125eedc0d4f3795b9e627269a4b5a6dca8257bdc04ad1885c127fe863abb00752fa844e6439bb04f264d70de7cea580b32637ab"
        ),
        // Vector #2
        TestVector(
            mnemonics = listOf(
                "hobby", "coil", "wisdom",
                "mechanic", "fossil", "pretty",
                "enough", "attract", "since",
                "choice", "exhaust", "hazard",
                "kit", "oven", "damp",
                "flip", "hawk", "tribe",
                "spice", "glare", "step",
                "hammer", "apple", "number"
            ),
            expectedSecretKeyHex = "764c63ecdc92b331caf3c5a81c483da8444d4ac87d87af9e3cd36ae207d94e5199ac861b19db16bc0f01adfc6897f4760dfc44f9415284c78689d4fcc28b94f7"
        ),
        // Vector #3
        TestVector(
            mnemonics = listOf(
                "now", "wide", "tag",
                "purity", "diamond", "coin",
                "unit", "rack", "device",
                "replace", "cheap", "deposit",
                "mention", "fence", "elite",
                "elder", "city", "measure",
                "reward", "lion", "chef",
                "promote", "depart", "connect"
            ),
            expectedSecretKeyHex = "2a8a63e0467f1f4148e0be0cc13e922d726f0b1c29272d6743eb83cf5549128f313abf58635fd310310d1debd54f4fe1fd63631ced044ba0af96b67b85eed31b"
        ),
        // Vector #4
        TestVector(
            mnemonics = listOf(
                "clinic", "toward", "wedding",
                "category", "tip", "spin",
                "purity", "absent", "army",
                "gun", "brain", "happy",
                "move", "company", "that",
                "cheap", "tank", "way",
                "shoe", "awkward", "pole",
                "protect", "wear", "crystal"
            ),
            expectedSecretKeyHex = "e5e78a8e1e509da180bc5aeb8af1a37d4311c5110402842925760a4035119362b1f8a0b9b4c2353ddfad8937ed396fb7670e88e8b72128b15006839a2a86be47"
        )
    )

    /**
     * Test all official @ton/crypto test vectors
     * 
     * Verifies that:
     * 1. The derived private key (seed) matches the first 32 bytes of expectedSecretKey
     * 2. The derived public key matches the last 32 bytes of expectedSecretKey
     */
    @Test
    fun testOfficialTonCryptoVectors() {
        for ((index, vector) in officialTestVectors.withIndex()) {
            val mnemonic = vector.mnemonics.joinToString(" ")
            val keyPair = Ton.keyPairFromMnemonic(mnemonic)
            
            // Expected secret key is 64 bytes: first 32 = seed (private key), last 32 = public key
            val expectedSecretKey = Hex.decode(vector.expectedSecretKeyHex)
            val expectedSeed = expectedSecretKey.sliceArray(0 until 32)
            val expectedPublicKey = expectedSecretKey.sliceArray(32 until 64)
            
            // Verify private key (seed)
            assertEquals(
                Hex.encode(expectedSeed),
                Hex.encode(keyPair.privateKey),
                "Vector #$index: Private key (seed) mismatch"
            )
            
            // Verify public key
            assertEquals(
                Hex.encode(expectedPublicKey),
                Hex.encode(keyPair.publicKey),
                "Vector #$index: Public key mismatch"
            )
        }
    }

    /**
     * Test V4R2 address generation format
     */
    @Test
    fun testAddressFormat() {
        // Use first official vector
        val mnemonic = officialTestVectors[0].mnemonics.joinToString(" ")
        val keyPair = Ton.keyPairFromMnemonic(mnemonic)
        
        // Generate bounceable mainnet address
        val bounceableAddress = Ton.getAddress(
            publicKey = keyPair.publicKey,
            workchain = 0,
            bounceable = true
        )
        
        // Generate non-bounceable mainnet address
        val nonBounceableAddress = Ton.getAddress(
            publicKey = keyPair.publicKey,
            workchain = 0,
            bounceable = false
        )
        
        // Verify format
        assertTrue(bounceableAddress.startsWith("EQ"), "Bounceable address should start with EQ, got: $bounceableAddress")
        assertTrue(nonBounceableAddress.startsWith("UQ"), "Non-bounceable address should start with UQ, got: $nonBounceableAddress")
        assertEquals(48, bounceableAddress.length, "Address should be 48 chars (Base64)")
        assertEquals(48, nonBounceableAddress.length, "Address should be 48 chars (Base64)")
    }

    /**
     * Test CRC16-CCITT (XMODEM variant, init 0x0000)
     * 
     * Standard test vector: "123456789" -> 0x31C3
     * Source: https://crccalc.com/ (CRC-16/XMODEM)
     */
    @Test
    fun testCrc16Xmodem() {
        val data = "123456789".encodeToByteArray()
        // CRC16-CCITT (XMODEM, poly 0x1021, init 0x0000, refin=false, refout=false)
        val expected = byteArrayOf(0x31.toByte(), 0xC3.toByte())
        val actual = Crc16.ccitt(data)
        
        assertEquals(Hex.encode(expected), Hex.encode(actual), "CRC16-XMODEM mismatch")
    }

    /**
     * Test wallet V4R2 wallet_id
     * 
     * Wallet ID for mainnet V4R2 is 698983191 (0x29a9a317)
     * Source: https://docs.ton.org/develop/smart-contracts/tutorials/wallet
     */
    @Test
    fun testWalletIdDefault() {
        // First vector
        val mnemonic = officialTestVectors[0].mnemonics.joinToString(" ")
        val keyPair = Ton.keyPairFromMnemonic(mnemonic)
        
        // Default wallet_id should be 698983191
        val addressDefault = Ton.getAddress(keyPair.publicKey)
        val addressExplicit = Ton.getAddress(keyPair.publicKey, walletId = 698983191)
        
        assertEquals(addressDefault, addressExplicit, "Default wallet_id should be 698983191")
    }
    
    /**
     * Test workchain parameter
     */
    @Test
    fun testWorkchainParameter() {
        val publicKey = ByteArray(32) { 0x01 }
        
        val mainchainAddress = Ton.getAddress(publicKey, workchain = 0)
        val masterchainAddress = Ton.getAddress(publicKey, workchain = -1)
        
        // Both should be valid format
        assertEquals(48, mainchainAddress.length)
        assertEquals(48, masterchainAddress.length)
        
        // They should be different (different workchain byte)
        assertTrue(mainchainAddress != masterchainAddress, "Different workchains should produce different addresses")
    }
}
