package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class XrpTest {

    // Official Vector: XRPL Genesis Account
    // Public Key: 0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020
    // Address: rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
    @Test
    fun testGenesisAddress() {
        val pubKeyHex = "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020"
        val expectedAddress = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        
        val pubKey = Hex.decode(pubKeyHex)
        val actualAddress = Xrp.getAddress(pubKey)
        
        assertEquals(expectedAddress, actualAddress)
        assertTrue(Xrp.isValidAddress(actualAddress))
    }

    @Test
    fun testValidation() {
        val valid = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"
        val invalidChecksum = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTi" // changed last char
        val invalidPrefix = "nHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"   // changed prefix
        val tooShort = "rShort"
        
        assertTrue(Xrp.isValidAddress(valid))
        assertFalse(Xrp.isValidAddress(invalidChecksum))
        assertFalse(Xrp.isValidAddress(invalidPrefix))
        assertFalse(Xrp.isValidAddress(tooShort))
    }
}
