package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class MoneroMnemonicTest {

    @Test
    fun testWordlistProperties() {
        val words = MoneroMnemonic.WORDS
        assertEquals(1626, words.size)
        
        // Verify 3-letter prefix uniqueness
        // Monero relies on the fact that the first 3 letters of each word are unique
        // so that the checksum can be compressed.
        val prefixes = words.map { if (it.length >= 3) it.substring(0, 3) else it }
        val uniquePrefixes = prefixes.toSet()
        
        // There should be no duplicate prefixes
        assertEquals(words.size, uniquePrefixes.size, "Wordlist must have unique 3-letter prefixes")
    }

    @Test
    fun testOfficialTestVectors() {
        // Source: https://xmr.llcoins.net/addresstests.html (Verified Mnemonic)
        val mnemonic = "lush bagpipe stacking mice imitate village gang efficient strained " +
                       "different together vain puck roped pancakes shocking liar moisture " +
                       "memoir sorry syndrome kettle swept dehydrate strained"
        
        val seed = MoneroMnemonic.decode(mnemonic)
        assertEquals(32, seed.size)
        
        // Re-encode should match exactly
        val reEncoded = MoneroMnemonic.encode(seed)
        assertEquals(mnemonic, reEncoded)
    }

    @Test
    fun testEdgeCases() {
        // 1. Invalid Word
        assertFailsWith<IllegalArgumentException> {
            MoneroMnemonic.decode("lush bagpipe stacking mice imitate village gang efficient strained " +
                    "different together vain puck roped pancakes shocking liar moisture " +
                    "memoir sorry syndrome kettle swept dehydrate aaaaaa") // 'aaaaaa' not in list
        }

        // 2. Invalid Checksum
        assertFailsWith<IllegalArgumentException> {
            MoneroMnemonic.decode("lush bagpipe stacking mice imitate village gang efficient strained " +
                    "different together vain puck roped pancakes shocking liar moisture " +
                    "memoir sorry syndrome kettle swept dehydrate efficient") // Valid word, wrong checksum
        }

        // 3. Invalid Length
        assertFailsWith<IllegalArgumentException> {
            val shortMnemonic = "lush bagpipe stacking mice imitate village gang efficient strained"
            MoneroMnemonic.decode(shortMnemonic)
        }
        
        // 4. Empty String
        assertFailsWith<IllegalArgumentException> {
            MoneroMnemonic.decode("")
        }
    }


    /**
     * Test Vector 2: Round Trip (Random Seed)
     */
    @Test
    fun testRoundTrip() {
        val seed = ByteArray(32) { it.toByte() } // 0, 1, 2, ...
        
        // Encode
        val mnemonic = MoneroMnemonic.encode(seed)
        val words = mnemonic.split(" ")
        assertEquals(25, words.size)
        
        // Decode
        val decodedSeed = MoneroMnemonic.decode(mnemonic)
        
        // Verify
        assertTrue(seed.contentEquals(decodedSeed), "Decoded seed should match original")
    }

    /**
     * Test Invalid Checksum
     */
    @Test
    fun testInvalidChecksum() {
        val validPhrase = "lush bagpipe stacking mice imitate village gang efficient strained " +
                          "different together vain puck roped pancakes shocking liar moisture " +
                          "memoir sorry syndrome kettle swept dehydrate strained"
        
        // Replace last word (checksum) with "memoir" (valid word but wrong checksum)
        val invalidPhrase = validPhrase.substringBeforeLast(" ") + " memoir"
        
        assertFailsWith<IllegalArgumentException> {
            MoneroMnemonic.decode(invalidPhrase)
        }
    }

    /**
     * Test Invalid Word
     */
    @Test
    fun testInvalidWord() {
        val validPhrase = "lush bagpipe stacking mice imitate village gang efficient strained " +
                          "different together vain puck roped pancakes shocking liar moisture " +
                          "memoir sorry syndrome kettle swept dehydrate strained"
                          
        // Replace first word with invalid word
        val invalidPhrase = "invalidword " + validPhrase.substringAfter(" ")
        
        assertFailsWith<IllegalArgumentException> {
            MoneroMnemonic.decode(invalidPhrase)
        }
    }
}
