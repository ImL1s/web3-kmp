package io.github.iml1s.tx.bitcoin

/**
 * PSBT 鍵值對
 */
data class PsbtKeyValuePair(
    val key: ByteArray,
    val value: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        other as PsbtKeyValuePair
        return key.contentEquals(other.key) && value.contentEquals(other.value)
    }

    override fun hashCode(): Int {
        var result = key.contentHashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}

/**
 * PSBT 映射 (Global, Input, Output)
 *
 * 由一系列鍵值對組成，以 0x00 鍵結尾
 */
open class PsbtMap(
    val map: MutableMap<String, ByteArray> = mutableMapOf(),
    // 保留原始順序和未知鍵
    val unknownKeys: MutableList<PsbtKeyValuePair> = mutableListOf()
) {
    fun addUnknownKey(key: ByteArray, value: ByteArray) {
        unknownKeys.add(PsbtKeyValuePair(key, value))
    }

    /**
     * 序列化映射
     */
    fun serialize(buffer: ByteArrayBuilder) {
        writeTypedFields(buffer)
        for (pair in unknownKeys) {
            writeKeyValuePair(buffer, pair.key, pair.value)
        }
        buffer.writeByte(0x00)
    }

    protected open fun writeTypedFields(buffer: ByteArrayBuilder) {}

    protected fun writeKeyValuePair(buffer: ByteArrayBuilder, key: ByteArray, value: ByteArray) {
        buffer.writeVarInt(key.size.toLong())
        buffer.writeBytes(key)
        buffer.writeVarInt(value.size.toLong())
        buffer.writeBytes(value)
    }
}

/**
 * PSBT 輸入 (Input Map)
 */
class PsbtInput : PsbtMap() {
    // 定義常用 Key Type
    companion object {
        const val PSBT_IN_NON_WITNESS_UTXO: Byte = 0x00
        const val PSBT_IN_WITNESS_UTXO: Byte = 0x01
        const val PSBT_IN_PARTIAL_SIG: Byte = 0x02
        const val PSBT_IN_SIGHASH_TYPE: Byte = 0x03
        const val PSBT_IN_REDEEM_SCRIPT: Byte = 0x04
        const val PSBT_IN_WITNESS_SCRIPT: Byte = 0x05
        const val PSBT_IN_BIP32_DERIVATION: Byte = 0x06
        const val PSBT_IN_FINAL_SCRIPTSIG: Byte = 0x07
        const val PSBT_IN_FINAL_SCRIPTWITNESS: Byte = 0x08
    }

    var nonWitnessUtxo: Transaction? = null
    var witnessUtxo: TxOutput? = null
    val partialSigs = mutableMapOf<String, ByteArray>() // PubKey (hex) -> Signature
    var sighashType: Int? = null
    var redeemScript: ByteArray? = null
    var witnessScript: ByteArray? = null
    val bip32Derivation = mutableMapOf<String, ByteArray>() // PubKey (hex) -> MasterFingerprint + Path
    var finalScriptSig: ByteArray? = null
    var finalScriptWitness: List<ByteArray>? = null

    override fun writeTypedFields(buffer: ByteArrayBuilder) {
        nonWitnessUtxo?.let {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_NON_WITNESS_UTXO), it.serializeWithoutWitness())
        }
        witnessUtxo?.let {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_WITNESS_UTXO), it.serialize())
        }
        for ((pub, sig) in partialSigs) {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_PARTIAL_SIG) + hexToBytes(pub), sig)
        }
        sighashType?.let { type ->
            val value = ByteArray(4)
            value[0] = (type and 0xFF).toByte()
            value[1] = ((type shr 8) and 0xFF).toByte()
            value[2] = ((type shr 16) and 0xFF).toByte()
            value[3] = ((type shr 24) and 0xFF).toByte()
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_SIGHASH_TYPE), value)
        }
        redeemScript?.let { writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_REDEEM_SCRIPT), it) }
        witnessScript?.let { writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_WITNESS_SCRIPT), it) }
        for ((pub, path) in bip32Derivation) {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_BIP32_DERIVATION) + hexToBytes(pub), path)
        }
        finalScriptSig?.let { writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_FINAL_SCRIPTSIG), it) }
        finalScriptWitness?.let { stack ->
            val b = ByteArrayBuilder()
            b.writeVarInt(stack.size.toLong())
            stack.forEach { item ->
                b.writeVarInt(item.size.toLong())
                b.writeBytes(item)
            }
            writeKeyValuePair(buffer, byteArrayOf(PSBT_IN_FINAL_SCRIPTWITNESS), b.toByteArray())
        }
    }
}

/**
 * PSBT 輸出 (Output Map)
 */
class PsbtOutput : PsbtMap() {
    companion object {
        const val PSBT_OUT_REDEEM_SCRIPT: Byte = 0x00
        const val PSBT_OUT_WITNESS_SCRIPT: Byte = 0x01
        const val PSBT_OUT_BIP32_DERIVATION: Byte = 0x02
    }

    var redeemScript: ByteArray? = null
    var witnessScript: ByteArray? = null
    val bip32Derivation = mutableMapOf<String, ByteArray>() // PubKey (hex) -> MasterFingerprint + Path

    override fun writeTypedFields(buffer: ByteArrayBuilder) {
        redeemScript?.let { writeKeyValuePair(buffer, byteArrayOf(PSBT_OUT_REDEEM_SCRIPT), it) }
        witnessScript?.let { writeKeyValuePair(buffer, byteArrayOf(PSBT_OUT_WITNESS_SCRIPT), it) }
        for ((pub, path) in bip32Derivation) {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_OUT_BIP32_DERIVATION) + hexToBytes(pub), path)
        }
    }
}

/**
 * Partially Signed Bitcoin Transaction (BIP174)
 */
class Psbt(
    val global: PsbtGlobal,
    val inputs: List<PsbtInput>,
    val outputs: List<PsbtOutput>
) {
    /**
     * 序列化 PSBT
     */
    fun serialize(): ByteArray {
        val buffer = ByteArrayBuilder()

        // 1. Magic Bytes (0x70736274ff) "psbt\xff"
        buffer.writeBytes(MAGIC_BYTES)

        // 2. Global Map
        global.serialize(buffer)

        // 3. Input Maps
        for (input in inputs) {
            input.serialize(buffer)
        }

        // 4. Output Maps
        for (output in outputs) {
            output.serialize(buffer)
        }

        return buffer.toByteArray()
    }

    companion object {
        val MAGIC_BYTES = byteArrayOf(0x70, 0x73, 0x62, 0x74, 0xFF.toByte())

        /**
         * 解析 PSBT 字節流
         */
        fun deserialize(data: ByteArray): Psbt {
            val reader = ByteArrayReader(data)

            val magic = reader.readBytes(5)
            require(magic.contentEquals(MAGIC_BYTES)) { "Invalid PSBT magic bytes" }

            val globalMap = readMap(reader)
            val global = PsbtGlobal.fromMap(globalMap)
            val unsigned = global.unsignedTx
                ?: throw IllegalArgumentException("PSBT v0 requires unsigned transaction")

            val inputs = mutableListOf<PsbtInput>()
            repeat(unsigned.inputs.size) {
                inputs.add(PsbtInput.fromMap(readMap(reader)))
            }
            val outputs = mutableListOf<PsbtOutput>()
            repeat(unsigned.outputs.size) {
                outputs.add(PsbtOutput.fromMap(readMap(reader)))
            }
            require(!reader.hasRemaining()) { "PSBT has trailing bytes" }

            return Psbt(global, inputs, outputs)
        }

        private fun readMap(reader: ByteArrayReader): List<PsbtKeyValuePair> {
            val pairs = mutableListOf<PsbtKeyValuePair>()
            val seen = mutableSetOf<String>()
            var sawSeparator = false
            while (reader.hasRemaining()) {
                val keyLenLong = reader.readVarInt()
                require(keyLenLong >= 0 && keyLenLong <= Int.MAX_VALUE) { "Invalid PSBT key length" }
                val keyLen = keyLenLong.toInt()
                if (keyLen == 0) {
                    sawSeparator = true
                    break
                }
                val key = reader.readBytes(keyLen)
                val keyHex = key.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }
                require(seen.add(keyHex)) { "Duplicate PSBT key" }
                val valueLenLong = reader.readVarInt()
                require(valueLenLong >= 0 && valueLenLong <= Int.MAX_VALUE) { "Invalid PSBT value length" }
                val value = reader.readBytes(valueLenLong.toInt())
                pairs.add(PsbtKeyValuePair(key, value))
            }
            require(sawSeparator) { "PSBT map missing separator" }
            return pairs
        }
    }
}

/**
 * PSBT Global Map
 */
class PsbtGlobal : PsbtMap() {
    companion object {
        const val PSBT_GLOBAL_UNSIGNED_TX: Byte = 0x00
        const val PSBT_GLOBAL_XPUB: Byte = 0x01
        const val PSBT_GLOBAL_VERSION: Byte = 0xFB.toByte()
        const val PSBT_GLOBAL_PROPRIETARY: Byte = 0xFC.toByte()

        fun fromMap(pairs: List<PsbtKeyValuePair>): PsbtGlobal {
            val global = PsbtGlobal()
            for (pair in pairs) {
                when {
                    pair.key.size == 1 && pair.key[0] == PSBT_GLOBAL_UNSIGNED_TX -> {
                        global.unsignedTx = Transaction.read(pair.value)
                    }
                    pair.key.size == 1 && pair.key[0] == PSBT_GLOBAL_VERSION -> {
                        require(pair.value.size == 4) { "Invalid PSBT version" }
                        global.version = pair.value[0].toInt() and 0xFF
                    }
                    else -> global.addUnknownKey(pair.key, pair.value)
                }
            }
            return global
        }
    }

    var unsignedTx: Transaction? = null
    var version: Int = 0
    val xpubs = mutableMapOf<String, String>() // XPub (hex) -> Fingerprint + Path (hex)

    override fun writeTypedFields(buffer: ByteArrayBuilder) {
        unsignedTx?.let {
            writeKeyValuePair(buffer, byteArrayOf(PSBT_GLOBAL_UNSIGNED_TX), it.serializeWithoutWitness())
        }
        if (version != 0) {
            val v = byteArrayOf(
                (version and 0xFF).toByte(),
                0, 0, 0
            )
            writeKeyValuePair(buffer, byteArrayOf(PSBT_GLOBAL_VERSION), v)
        }
    }
}

private fun hexToBytes(hex: String): ByteArray {
    val s = if (hex.length % 2 == 0) hex else "0$hex"
    return ByteArray(s.length / 2) { i ->
        ((s[i * 2].digitToInt(16) shl 4) + s[i * 2 + 1].digitToInt(16)).toByte()
    }
}

private fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }

internal fun PsbtInput.Companion.fromMap(pairs: List<PsbtKeyValuePair>): PsbtInput {
    val input = PsbtInput()
    for (pair in pairs) {
        val type = pair.key.firstOrNull()
        when {
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_NON_WITNESS_UTXO -> {
                input.nonWitnessUtxo = Transaction.read(pair.value)
            }
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_WITNESS_UTXO -> {
                input.witnessUtxo = TxOutput.read(pair.value)
            }
            type == PsbtInput.PSBT_IN_PARTIAL_SIG && pair.key.size > 1 -> {
                input.partialSigs[bytesToHex(pair.key.copyOfRange(1, pair.key.size))] = pair.value
            }
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_SIGHASH_TYPE -> {
                require(pair.value.size == 4) { "Invalid sighash type" }
                input.sighashType = (pair.value[0].toInt() and 0xFF) or
                    ((pair.value[1].toInt() and 0xFF) shl 8) or
                    ((pair.value[2].toInt() and 0xFF) shl 16) or
                    ((pair.value[3].toInt() and 0xFF) shl 24)
            }
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_REDEEM_SCRIPT -> input.redeemScript = pair.value
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_WITNESS_SCRIPT -> input.witnessScript = pair.value
            type == PsbtInput.PSBT_IN_BIP32_DERIVATION && pair.key.size > 1 -> {
                input.bip32Derivation[bytesToHex(pair.key.copyOfRange(1, pair.key.size))] = pair.value
            }
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_FINAL_SCRIPTSIG -> input.finalScriptSig = pair.value
            pair.key.size == 1 && type == PsbtInput.PSBT_IN_FINAL_SCRIPTWITNESS -> {
                val reader = ByteArrayReader(pair.value)
                val count = reader.readVarInt().toInt()
                require(count >= 0) { "Invalid final script witness count" }
                input.finalScriptWitness = (0 until count).map { reader.readScript() }
            }
            else -> input.addUnknownKey(pair.key, pair.value)
        }
    }
    return input
}

internal fun PsbtOutput.Companion.fromMap(pairs: List<PsbtKeyValuePair>): PsbtOutput {
    val output = PsbtOutput()
    for (pair in pairs) {
        val type = pair.key.firstOrNull()
        when {
            pair.key.size == 1 && type == PsbtOutput.PSBT_OUT_REDEEM_SCRIPT -> output.redeemScript = pair.value
            pair.key.size == 1 && type == PsbtOutput.PSBT_OUT_WITNESS_SCRIPT -> output.witnessScript = pair.value
            type == PsbtOutput.PSBT_OUT_BIP32_DERIVATION && pair.key.size > 1 -> {
                output.bip32Derivation[bytesToHex(pair.key.copyOfRange(1, pair.key.size))] = pair.value
            }
            else -> output.addUnknownKey(pair.key, pair.value)
        }
    }
    return output
}
