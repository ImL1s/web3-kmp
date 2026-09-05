package io.github.iml1s.tx.bitcoin

import io.github.iml1s.tx.utils.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * BIP-143 native P2WPKH official vector.
 * https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
 *
 * Official sighash: c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670
 * Doubled scriptCode CompactSize (the bug) hashes to 7e58a8552e119dbf5150469fb8900aa29f18962d89b481fe36a7395c211432f8
 */
class Bip143P2wpkhTest {

    private val unsignedHex =
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffff" +
            "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff" +
            "02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac" +
            "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"

    private val officialSighash = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    private val doubledLengthSighash = "7e58a8552e119dbf5150469fb8900aa29f18962d89b481fe36a7395c211432f8"

    @Test
    fun nativeP2wpkhOfficialSighash() {
        val tx = Transaction.read(unsignedHex)
        val scriptCode = Hex.decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
        val amount = 6_0000_0000L
        val preimage = tx.bip143SignaturePreimage(1, scriptCode, Transaction.SIGHASH_ALL, amount)
        val compactIndex = indexOf(preimage, Hex.decode("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"))
        assertTrue(compactIndex >= 0, "preimage must contain a single CompactSize scriptCode")
        assertFalse(indexOf(preimage, Hex.decode("1a1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")) >= 0)

        val sighash = tx.hashForSignature(1, scriptCode, Transaction.SIGHASH_ALL, amount, isSegWit = true)
        assertEquals(officialSighash, Hex.encode(sighash))
        assertTrue(Hex.encode(sighash) != doubledLengthSighash)
    }

    @Test
    fun signP2wpkhUsesRawScriptCode() {
        val tx = Transaction.read(unsignedHex)
        val priv = Hex.decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
        val pub = Hex.decode("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
        val witness = Signer.signP2WPKH(tx, 1, priv, pub, 6_0000_0000L)
        assertEquals(2, witness.stack.size)
        assertEquals(pub.toList(), witness.stack[1].toList())
        assertEquals(Transaction.SIGHASH_ALL.toByte(), witness.stack[0].last())
    }

    @Test
    fun noneDoesNotCommitToOutputs() {
        val tx = twoInTwoOut()
        val script = ByteArray(25) { 0x51 }
        val none = tx.hashForSignature(0, script, Transaction.SIGHASH_NONE)
        val mutated = tx.copy(outputs = listOf(TxOutput(1, byteArrayOf(0x51)), tx.outputs[1]))
        val noneMut = mutated.hashForSignature(0, script, Transaction.SIGHASH_NONE)
        assertEquals(Hex.encode(none), Hex.encode(noneMut))
        val all = tx.hashForSignature(0, script, Transaction.SIGHASH_ALL)
        val allMut = mutated.hashForSignature(0, script, Transaction.SIGHASH_ALL)
        assertTrue(Hex.encode(all) != Hex.encode(allMut))
    }

    @Test
    fun taprootRejectsIllegalHashTypeAndMissingSingle() {
        val tx = twoInTwoOut()
        val prev = tx.outputs
        assertFails { tx.hashForSigningTaprootKeyPath(0, prev, 0x04) }
        assertFails { tx.hashForSigningTaprootKeyPath(0, prev, 0xff) }
        val oneOut = tx.copy(outputs = listOf(tx.outputs[0]))
        assertFails { oneOut.hashForSigningTaprootKeyPath(1, listOf(prev[0], prev[1]), Transaction.SIGHASH_SINGLE) }
    }

    private fun twoInTwoOut(): Transaction {
        return Transaction(
            version = 1,
            inputs = listOf(
                TxInput(ByteArray(32) { 1 }, 0, sequence = 0xffffffffL),
                TxInput(ByteArray(32) { 2 }, 1, sequence = 0xffffffffL)
            ),
            outputs = listOf(
                TxOutput(1000, byteArrayOf(0x51)),
                TxOutput(2000, byteArrayOf(0x51, 0x51))
            )
        )
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }
}
