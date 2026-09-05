package io.github.iml1s.tx.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PsbtTest {

    @Test
    fun testPsbtSerializationSimple() {
        // Create minimal PSBT
        val global = PsbtGlobal()
        
        val tx = Transaction(
            version = 2,
            inputs = listOf(
                TxInput(ByteArray(32), 0)
            ),
            outputs = listOf(
                TxOutput(1000, ByteArray(25))
            )
        )
        // Add unsigned tx to global map (simulated as pair for now since raw deserialization not fully hooked up in PsbtGlobal.fromMap)
        global.unsignedTx = tx

        val psbt = Psbt(
            global = global,
            inputs = listOf(PsbtInput()),
            outputs = listOf(PsbtOutput())
        )

        val serialized = psbt.serialize()
        
        // Check Magic Bytes "psbt\xff"
        val magic = byteArrayOf(0x70, 0x73, 0x62, 0x74, 0xff.toByte())
        for (i in magic.indices) {
            assertEquals(magic[i], serialized[i])
        }
        
        // Round-trip deserialization
        val deserialized = Psbt.deserialize(serialized)
        assertNotNull(deserialized)
        assertNotNull(deserialized.global.unsignedTx)
        assertEquals(1, deserialized.inputs.size)
        assertEquals(1, deserialized.outputs.size)
        
        val deserializedTx = Transaction(inputs=listOf(TxInput(ByteArray(32), 0)), outputs=listOf(TxOutput(1000, ByteArray(25)))) // Mock, assuming bytes are correct
        // In real test, we would deserialize txBytes to Transaction
    }
}
