package io.github.iml1s.tx.bitcoin

import kotlin.test.*

class TransactionSerializationTest {

    @Test
    fun testLegacyTransactionSerialization() {
        // A simple legacy transaction
        val tx = Transaction(
            version = 1,
            inputs = listOf(
                TxInput(
                    previousTxHash = ByteArray(32) { 0x01 },
                    previousOutputIndex = 0,
                    scriptSig = "00".hexToByteArray(),
                    sequence = TxInput.SEQUENCE_FINAL
                )
            ),
            outputs = listOf(
                TxOutput(
                    value = 1000,
                    scriptPubKey = "76a914000000000000000000000000000000000000000088ac".hexToByteArray()
                )
            ),
            lockTime = 0
        )

        val serialized = tx.serialize()
        val hex = serialized.toHexString()
        
        // Expected components:
        // Version: 01000000
        // Inputs count: 01
        // PrevHash: 01...01
        // Index: 00000000
        // Script length: 01
        // ScriptSig: 00
        // Sequence: ffffffff
        // Outputs count: 01
        // Value: e803000000000000 (1000)
        // ScriptPubKey length: 19 (25 bytes)
        // ScriptPubKey: 76a914...88ac
        // Locktime: 00000000
        assertTrue(hex.startsWith("0100000001010101"))
        assertTrue(hex.contains("e803000000000000"))
        assertTrue(hex.endsWith("00000000"))
    }

    @Test
    fun testSegWitTransactionStructure() {
        // According to BIP-141, a SegWit transaction MUST have marker 0x00 and flag 0x01
        val tx = Transaction(
            version = 1,
            inputs = listOf(
                TxInput(
                    previousTxHash = ByteArray(32) { 0x02 },
                    previousOutputIndex = 0,
                    scriptSig = ByteArray(0),
                    sequence = TxInput.SEQUENCE_FINAL
                )
            ),
            outputs = listOf(
                TxOutput(
                    value = 1000,
                    scriptPubKey = "00140101010101010101010101010101010101010101".hexToByteArray()
                )
            ),
            witnesses = listOf(
                TxWitness(listOf("signature".encodeToByteArray(), "pubkey".encodeToByteArray()))
            ),
            lockTime = 0
        )

        val serialized = tx.serialize()
        val hex = serialized.toHexString()

        // BIP-141 SegWit format: [nVersion][marker][flag][txins][txouts][witness][nLockTime]
        // marker=00, flag=01
        // Hex index 8-10 should be '00', 10-12 should be '01'
        assertEquals("00", hex.substring(8, 10), "Marker must be 00")
        assertEquals("01", hex.substring(10, 12), "Flag must be 01")
        
        // Test serializeWithoutWitness
        val legacyHex = tx.serializeWithoutWitness().toHexString()
        assertFalse(legacyHex.contains("signature".encodeToByteArray().toHexString()), "Legacy serialization must not contain witness")
    }

    @Test
    fun testVSizeCalculation() {
        val witness = TxWitness(listOf(ByteArray(100))) 
        val tx = Transaction(
            inputs = listOf(TxInput(ByteArray(32), 0, ByteArray(0))),
            outputs = listOf(TxOutput(1000, "00".hexToByteArray())),
            witnesses = listOf(witness)
        )

        val totalSize = tx.serialize().size
        val weight = tx.getWeight()
        val vSize = tx.getVirtualSize()
        
        // Virtual size formula: ceil(Weight / 4)
        assertEquals((weight + 3) / 4, vSize)
        assertTrue(vSize < totalSize, "vSize should be smaller than raw size for SegWit transactions")
    }

    private fun String.hexToByteArray(): ByteArray {
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
}
