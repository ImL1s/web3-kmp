package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertTrue

/**
 * BIP32 CKDpriv must reject parse256(IL) >= n before modulo.
 * Fixture IL is the secp256k1 order itself (32-byte big-endian n).
 */
class Bip32P1Test {

    @Test
    fun deriveChildRejectsIlGreaterThanOrEqualN() {
        val parent = Bip32.masterKeyFromSeed(ByteArray(64) { 1 })
        // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        val ilEqN = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
        val ex = assertFails { Bip32.childPrivateKeyFromIl(ilEqN, parent.privateKey) }
        assertTrue(ex.message!!.contains("IL >= curve order"))

        val ilAboveN = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        assertFails { Bip32.childPrivateKeyFromIl(ilAboveN, parent.privateKey) }

        // A small IL still combines (proves the seam is the real CKDpriv adder).
        val child = Bip32.childPrivateKeyFromIl(ByteArray(32) { 0 }.also { it[31] = 1 }, parent.privateKey)
        assertTrue(child.size == 32)
        assertTrue(child.any { it != 0.toByte() })
    }
}
