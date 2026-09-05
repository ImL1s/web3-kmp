package io.github.iml1s.address

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * BIP-173 / BIP-350 negative cases that the production decoder must reject.
 * Mixed-case vector from BIP-173 invalid addresses.
 * https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 */
class Bech32P1Test {

    @Test
    fun mixedCaseIsRejected() {
        // BIP-173 invalid: mixed case
        val mixed = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7"
        assertNull(Bech32.decode(mixed))
        assertNull(Bech32.decodeSegwitAddress(mixed))
    }

    @Test
    fun invalidHrpIsRejectedForSegwit() {
        assertNull(Bech32.decodeSegwitAddress("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"))
    }

    @Test
    fun witnessProgramLengthRejected() {
        // BIP-173: empty data / too short
        assertNull(Bech32.decodeSegwitAddress("bc1gmk9yu"))
        // v0 program must be 20 or 32 bytes
        assertNull(Bech32.decodeSegwitAddress("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"))
    }

    @Test
    fun officialValidP2wpkhRoundTrip() {
        // BIP-173 valid: BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4
        val addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        val decoded = Bech32.decodeSegwitAddress(addr)
        assertNotNull(decoded)
        assertEquals(0, decoded.first)
        assertEquals(20, decoded.second.size)
        val encoded = Bech32.encodeSegwitAddress("bc", decoded.first, decoded.second)
        assertEquals(addr, encoded)
    }
}
