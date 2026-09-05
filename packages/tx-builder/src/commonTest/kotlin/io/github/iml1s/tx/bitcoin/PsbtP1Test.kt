package io.github.iml1s.tx.bitcoin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PsbtP1Test {

    @Test
    fun magicOnlyFailsClosed() {
        val magicOnly = byteArrayOf(0x70, 0x73, 0x62, 0x74, 0xff.toByte())
        assertFails { Psbt.deserialize(magicOnly) }
    }

    @Test
    fun roundTripKeepsUnsignedTxAndWitnessUtxo() {
        val tx = Transaction(
            version = 2,
            inputs = listOf(TxInput(ByteArray(32) { 3 }, 0)),
            outputs = listOf(TxOutput(1000, ByteArray(25) { 0x51 }))
        )
        val global = PsbtGlobal().apply { unsignedTx = tx }
        val input = PsbtInput().apply {
            witnessUtxo = TxOutput(1000, byteArrayOf(0x00, 0x14) + ByteArray(20))
            partialSigs["025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"] =
                byteArrayOf(0x30, 0x02, 0x01, 0x01)
        }
        val output = PsbtOutput().apply { redeemScript = byteArrayOf(0x51) }
        val serialized = Psbt(global, listOf(input), listOf(output)).serialize()
        val parsed = Psbt.deserialize(serialized)
        assertNotNull(parsed.global.unsignedTx)
        assertEquals(1, parsed.inputs.size)
        assertNotNull(parsed.inputs[0].witnessUtxo)
        assertEquals(1000, parsed.inputs[0].witnessUtxo!!.value)
        assertTrue(parsed.inputs[0].partialSigs.isNotEmpty())
        assertEquals(byteArrayOf(0x51).toList(), parsed.outputs[0].redeemScript!!.toList())
        assertEquals(0xFC.toByte(), PsbtGlobal.PSBT_GLOBAL_PROPRIETARY)
    }

    @Test
    fun roundTripKeepsFinalScriptWitness() {
        val tx = Transaction(
            version = 2,
            inputs = listOf(TxInput(ByteArray(32) { 7 }, 1)),
            outputs = listOf(TxOutput(500, byteArrayOf(0x51)))
        )
        val global = PsbtGlobal().apply { unsignedTx = tx }
        val input = PsbtInput().apply {
            finalScriptWitness = listOf(byteArrayOf(0x30, 0x02, 0x01, 0x01), byteArrayOf(0x21) + ByteArray(32) { 2 })
        }
        val parsed = Psbt.deserialize(Psbt(global, listOf(input), listOf(PsbtOutput())).serialize())
        val got = parsed.inputs[0].finalScriptWitness
        assertNotNull(got)
        assertEquals(2, got.size)
        assertEquals(input.finalScriptWitness!![0].toList(), got[0].toList())
        assertEquals(input.finalScriptWitness!![1].toList(), got[1].toList())
    }

    @Test
    fun duplicateFullKeyRejected() {
        val tx = Transaction(
            version = 2,
            inputs = listOf(TxInput(ByteArray(32), 0)),
            outputs = listOf(TxOutput(1, byteArrayOf(0x51)))
        )
        val unsigned = tx.serializeWithoutWitness()
        val builder = ByteArrayBuilder()
        builder.writeBytes(Psbt.MAGIC_BYTES)
        // key 0x00 twice
        fun kv(key: ByteArray, value: ByteArray) {
            builder.writeVarInt(key.size.toLong())
            builder.writeBytes(key)
            builder.writeVarInt(value.size.toLong())
            builder.writeBytes(value)
        }
        kv(byteArrayOf(0x00), unsigned)
        kv(byteArrayOf(0x00), unsigned)
        builder.writeByte(0x00)
        builder.writeByte(0x00) // input map
        builder.writeByte(0x00) // output map
        assertFails { Psbt.deserialize(builder.toByteArray()) }
    }
}
