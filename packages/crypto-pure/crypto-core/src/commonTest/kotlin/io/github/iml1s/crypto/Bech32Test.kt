package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFails
import kotlin.test.fail

class Bech32Test {

    @Test
    fun testBip173Valid() {
        val valid = listOf(
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl"
        )
        
        for (s in valid) {
            try {
                val decoded = Bech32.decode(s)
                val recoded = Bech32.encode(decoded.hrp, decoded.data, Bech32.Spec.BECH32)
                assertEquals(s.lowercase(), recoded.lowercase())
                assertEquals(Bech32.Spec.BECH32, decoded.spec)
            } catch (e: Exception) {
                fail("Failed for vector: $s, Error: ${e.message}")
            }
        }
    }
    
    @Test
    fun testBip350Valid() {
        val valid = listOf(
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa"
        )



        
        for (s in valid) {
            try {
                val decoded = Bech32.decode(s)
                val recoded = Bech32.encode(decoded.hrp, decoded.data, Bech32.Spec.BECH32M)
                assertEquals(s.lowercase(), recoded.lowercase())
                assertEquals(Bech32.Spec.BECH32M, decoded.spec)
            } catch (e: Exception) {
                fail("Failed for vector: $s, Error: ${e.message}")
            }
        }
    }
    
    @Test
    fun testInvalid() {
        val invalid = listOf(
            " 1nwldj5", // HRP character out of range
            "0x1nwldj5", // HRP character out of range
            // "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", // REMOVED: limit increased for Cardano
            "pzry9x0s0muk", // No separator character
            "1pzry9x0s0muk", // Empty HRP
            "x1b4n0q5v", // Invalid data character
            "li1dgmt3", // Too short checksum
            "de1lg7wt" + "\u00ff", // Invalid character in checksum
            "A1G7SGD8", // checksum calculated with uppercase HRP
            "10a06t8", // empty HRP
            "1qzzfhee", // empty HRP
        )
        
        for (s in invalid) {
            assertFails { Bech32.decode(s) }
        }
    }
}
