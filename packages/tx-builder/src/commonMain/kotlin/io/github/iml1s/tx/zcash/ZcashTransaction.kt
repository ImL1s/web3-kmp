package io.github.iml1s.tx.zcash

import io.github.iml1s.tx.bitcoin.*
import io.github.iml1s.tx.crypto.Crypto

/**
 * Zcash 版本組 ID
 * 
 * 用於區分不同的網路升級版本
 * @see <a href="https://zips.z.cash/protocol/protocol.pdf">Zcash Protocol Specification</a>
 */
object ZcashVersionGroup {
    /** Overwinter (ZIP-143) */
    const val OVERWINTER: Int = 0x03C48270
    
    /** Sapling (ZIP-243) */
    @Suppress("INTEGER_OVERFLOW")
    val SAPLING: Int = 0x892F2085.toInt()
    
    /** NU5/Canopy */
    @Suppress("INTEGER_OVERFLOW")
    val NU5: Int = 0x26A7270A
}

/**
 * Zcash 分支 ID
 */
object ZcashBranchId {
    @Suppress("INTEGER_OVERFLOW") val OVERWINTER: Int = 0x5BA81B19.toInt()
    @Suppress("INTEGER_OVERFLOW") val SAPLING: Int = 0x76B809BB.toInt()
    val BLOSSOM: Int = 0x2BB40E60
    @Suppress("INTEGER_OVERFLOW") val HEARTWOOD: Int = 0xF5B9230B.toInt()
    @Suppress("INTEGER_OVERFLOW") val CANOPY: Int = 0xE9FF75A6.toInt()
    @Suppress("INTEGER_OVERFLOW") val NU5: Int = 0xC2D6D0B4.toInt()
}

/**
 * Zcash 透明交易 (T-addr)
 * 
 * 擴展 Bitcoin 交易格式，加入:
 * - 版本組 ID (nVersionGroupId)
 * - 過期高度 (nExpiryHeight)
 * - Sapling valueBalance
 * 
 * 格式 (Sapling):
 * ```
 * [header:4][nVersionGroupId:4][...inputs...][...outputs...][nLockTime:4]
 * [nExpiryHeight:4][valueBalance:8][nShieldedSpend:varint][nShieldedOutput:varint]
 * [nJoinSplit:varint]
 * ```
 * 
 * @see <a href="https://zips.z.cash/zip-0243">ZIP-243 Sapling Transaction Format</a>
 */
data class ZcashTransaction(
    /**
     * 交易版本
     * 4 = Sapling 透明交易
     * 5 = NU5 透明交易
     */
    val version: Int = 4,
    
    /** 版本組 ID */
    val versionGroupId: Int = ZcashVersionGroup.SAPLING,
    
    /** 交易輸入 */
    val inputs: List<TxInput>,
    
    /** 交易輸出 */
    val outputs: List<TxOutput>,
    
    /** 鎖定時間 */
    val lockTime: Long = 0,
    
    /** 過期區塊高度 (0 = 永不過期) */
    val expiryHeight: Int = 0,
    
    /** 
     * Sapling value balance 
     * 正數 = Shielded -> Transparent (de-shield)
     * 負數 = Transparent -> Shielded (shield)
     * 透明交易設為 0
     */
    val valueBalance: Long = 0,
    
    /** 分支 ID (用於簽名) */
    val branchId: Int = ZcashBranchId.SAPLING
) {
    init {
        require(inputs.isNotEmpty()) { "Transaction must have at least one input" }
        require(outputs.isNotEmpty()) { "Transaction must have at least one output" }
    }

    /**
     * 取得 header 欄位
     * 高位元組: fOverwintered (1) | 0000 (4 bits)
     * 低 31 位元: version
     */
    private fun getHeader(): Int {
        return (1 shl 31) or version
    }

    /**
     * 計算 txid
     */
    val txid: TxId get() = TxId(doubleSha256(serialize()))

    /**
     * 序列化交易 (透明交易)
     */
    fun serialize(): ByteArray {
        val buffer = ByteArrayBuilder()

        // Header (with fOverwintered flag)
        buffer.writeInt32LE(getHeader())

        // nVersionGroupId
        buffer.writeInt32LE(versionGroupId)

        // Inputs
        buffer.writeVarInt(inputs.size.toLong())
        for (input in inputs) {
            buffer.writeBytes(input.previousTxHash)
            buffer.writeInt32LE(input.previousOutputIndex.toInt())
            buffer.writeVarInt(input.scriptSig.size.toLong())
            buffer.writeBytes(input.scriptSig)
            buffer.writeInt32LE(input.sequence.toInt())
        }

        // Outputs
        buffer.writeVarInt(outputs.size.toLong())
        for (output in outputs) {
            buffer.writeInt64LE(output.value)
            buffer.writeVarInt(output.scriptPubKey.size.toLong())
            buffer.writeBytes(output.scriptPubKey)
        }

        // nLockTime
        buffer.writeInt32LE(lockTime.toInt())

        // nExpiryHeight
        buffer.writeInt32LE(expiryHeight.toInt())

        // valueBalance (Sapling)
        if (version >= 4) {
            buffer.writeInt64LE(valueBalance)
        }

        // Shielded Spends (empty for transparent)
        buffer.writeVarInt(0)

        // Shielded Outputs (empty for transparent)
        buffer.writeVarInt(0)

        // JoinSplits (empty, deprecated)
        if (version == 4) {
            buffer.writeVarInt(0)
        }

        return buffer.toByteArray()
    }

    /**
     * ZIP-243 簽名哈希 (Sapling)
     */
    fun hashForSignature(
        inputIndex: Int,
        scriptCode: ByteArray,
        amount: Long,
        hashType: Int = SIGHASH_ALL
    ): ByteArray {
        require(inputIndex in inputs.indices) { "Invalid input index" }

        val buffer = ByteArrayBuilder()

        // 1. Header
        buffer.writeInt32LE(getHeader())

        // 2. nVersionGroupId
        buffer.writeInt32LE(versionGroupId)

        // 3. hashPrevouts
        if ((hashType and SIGHASH_ANYONECANPAY) == 0) {
            val prevouts = ByteArrayBuilder()
            inputs.forEach { input ->
                prevouts.writeBytes(input.previousTxHash)
                prevouts.writeInt32LE(input.previousOutputIndex.toInt())
            }
            buffer.writeBytes(doubleSha256(prevouts.toByteArray()))
        } else {
            buffer.writeBytes(ByteArray(32))
        }

        // 4. hashSequence
        if ((hashType and SIGHASH_ANYONECANPAY) == 0 &&
            (hashType and 0x1f) != SIGHASH_SINGLE &&
            (hashType and 0x1f) != SIGHASH_NONE
        ) {
            val sequences = ByteArrayBuilder()
            inputs.forEach { input ->
                sequences.writeInt32LE(input.sequence.toInt())
            }
            buffer.writeBytes(doubleSha256(sequences.toByteArray()))
        } else {
            buffer.writeBytes(ByteArray(32))
        }

        // 5. hashOutputs
        if ((hashType and 0x1f) != SIGHASH_SINGLE && (hashType and 0x1f) != SIGHASH_NONE) {
            val outs = ByteArrayBuilder()
            outputs.forEach { output ->
                outs.writeInt64LE(output.value)
                outs.writeVarInt(output.scriptPubKey.size.toLong())
                outs.writeBytes(output.scriptPubKey)
            }
            buffer.writeBytes(doubleSha256(outs.toByteArray()))
        } else if ((hashType and 0x1f) == SIGHASH_SINGLE && inputIndex < outputs.size) {
            val out = outputs[inputIndex]
            val singleOut = ByteArrayBuilder()
            singleOut.writeInt64LE(out.value)
            singleOut.writeVarInt(out.scriptPubKey.size.toLong())
            singleOut.writeBytes(out.scriptPubKey)
            buffer.writeBytes(doubleSha256(singleOut.toByteArray()))
        } else {
            buffer.writeBytes(ByteArray(32))
        }

        // 6. hashJoinSplits (empty)
        buffer.writeBytes(ByteArray(32))

        // 7. hashShieldedSpends (empty)
        buffer.writeBytes(ByteArray(32))

        // 8. hashShieldedOutputs (empty)
        buffer.writeBytes(ByteArray(32))

        // 9. nLockTime
        buffer.writeInt32LE(lockTime.toInt())

        // 10. nExpiryHeight
        buffer.writeInt32LE(expiryHeight.toInt())

        // 11. valueBalance
        buffer.writeInt64LE(valueBalance)

        // 12. nHashType
        buffer.writeInt32LE(hashType)

        // 13. Input being signed
        val input = inputs[inputIndex]
        buffer.writeBytes(input.previousTxHash)
        buffer.writeInt32LE(input.previousOutputIndex.toInt())

        // 14. scriptCode
        buffer.writeVarInt(scriptCode.size.toLong())
        buffer.writeBytes(scriptCode)

        // 15. amount
        buffer.writeInt64LE(amount)

        // 16. nSequence
        buffer.writeInt32LE(input.sequence.toInt())

        // BLAKE2b-256 with personalization "ZcashSigHash" + branchId
        return blake2bSigHash(buffer.toByteArray())
    }

    private fun blake2bSigHash(data: ByteArray): ByteArray {
        val personalization = ByteArray(16)
        "ZcashSigHash".encodeToByteArray().copyInto(personalization)
        personalization[12] = (branchId and 0xFF).toByte()
        personalization[13] = ((branchId shr 8) and 0xFF).toByte()
        personalization[14] = ((branchId shr 16) and 0xFF).toByte()
        personalization[15] = ((branchId shr 24) and 0xFF).toByte()
        
        return io.github.iml1s.crypto.Blake2b.digest(
            data = data,
            personalization = personalization,
            digestSize = 32
        )
    }

    private fun doubleSha256(data: ByteArray): ByteArray {
        return sha256(sha256(data))
    }

    private fun sha256(data: ByteArray): ByteArray {
        return Crypto.sha256(data)
    }

    companion object {
        const val SIGHASH_ALL = 0x01
        const val SIGHASH_NONE = 0x02
        const val SIGHASH_SINGLE = 0x03
        const val SIGHASH_ANYONECANPAY = 0x80
    }
}

/**
 * Zcash 透明交易建構器
 */
class ZcashTxBuilder {
    private var version: Int = 4
    private var versionGroupId: Int = ZcashVersionGroup.SAPLING
    private var branchId: Int = ZcashBranchId.SAPLING
    private val inputs = mutableListOf<TxInput>()
    private val outputs = mutableListOf<TxOutput>()
    private var lockTime: Long = 0
    private var expiryHeight: Int = 0

    fun version(version: Int) = apply { this.version = version }
    fun versionGroupId(id: Int) = apply { this.versionGroupId = id }
    fun branchId(id: Int) = apply { this.branchId = id }
    fun lockTime(lockTime: Long) = apply { this.lockTime = lockTime }
    fun expiryHeight(height: Int) = apply { this.expiryHeight = height }

    fun addInput(
        txid: ByteArray,
        vout: Int,
        scriptSig: ByteArray = ByteArray(0),
        sequence: Long = TxInput.SEQUENCE_FINAL
    ) = apply {
        inputs.add(TxInput(txid.reversedArray(), vout.toLong(), scriptSig, sequence))
    }

    fun addOutput(value: Long, scriptPubKey: ByteArray) = apply {
        outputs.add(TxOutput(value, scriptPubKey))
    }

    fun build(): ZcashTransaction {
        require(inputs.isNotEmpty()) { "Must have at least one input" }
        require(outputs.isNotEmpty()) { "Must have at least one output" }

        return ZcashTransaction(
            version = version,
            versionGroupId = versionGroupId,
            inputs = inputs.toList(),
            outputs = outputs.toList(),
            lockTime = lockTime,
            expiryHeight = expiryHeight,
            branchId = branchId
        )
    }
}
