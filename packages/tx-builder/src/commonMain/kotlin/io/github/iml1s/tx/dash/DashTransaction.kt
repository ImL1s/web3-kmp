package io.github.iml1s.tx.dash

import io.github.iml1s.tx.bitcoin.*
import io.github.iml1s.tx.crypto.Crypto

/**
 * Dash 交易類型
 * 
 * Dash 使用 32-bit 版本欄位:
 * - 低 16 bits: 版本號 (通常是 3)
 * - 高 16 bits: 交易類型
 * 
 * @see <a href="https://docs.dash.org/en/latest/docs/core-reference/transactions-special-transactions.html">Dash Special Transactions</a>
 */
enum class DashTxType(val value: Int) {
    /** 標準交易 */
    STANDARD(0),
    
    /** 註冊/更新 Masternode Provider (ProRegTx) */
    PRO_REG_TX(1),
    
    /** 更新 Masternode Service (ProUpServTx) */
    PRO_UP_SERV_TX(2),
    
    /** 更新 Masternode Registrar (ProUpRegTx) */
    PRO_UP_REG_TX(3),
    
    /** 撤銷 Masternode (ProUpRevTx) */
    PRO_UP_REV_TX(4),
    
    /** Coinbase (區塊獎勵) */
    COINBASE(5),
    
    /** Quorum Commitment */
    QUORUM_COMMITMENT(6),
    
    /** 資產鎖定 */
    ASSET_LOCK(8),
    
    /** 資產解鎖 */
    ASSET_UNLOCK(9);

    companion object {
        fun fromValue(value: Int): DashTxType = 
            values().find { it.value == value } ?: STANDARD
    }
}

/**
 * Dash 交易
 * 
 * 擴展 Bitcoin 交易，支援:
 * - 版本 3 (DIP-0002)
 * - 特殊交易類型 (DIP-0002)
 * - 額外負載資料 (extraPayload)
 * 
 * 格式:
 * ```
 * [version:4][type:2 (if v3)][...標準 tx 資料...][extraPayloadSize:varint][extraPayload:...]
 * ```
 * 
 * @see <a href="https://github.com/dashpay/dips/blob/master/dip-0002.md">DIP-0002</a>
 */
data class DashTransaction(
    /** 交易版本 (通常為 3) */
    val version: Int = 3,
    
    /** 交易類型 */
    val type: DashTxType = DashTxType.STANDARD,
    
    /** 交易輸入 */
    val inputs: List<TxInput>,
    
    /** 交易輸出 */
    val outputs: List<TxOutput>,
    
    /** 見證資料 */
    val witnesses: List<TxWitness> = emptyList(),
    
    /** 鎖定時間 */
    val lockTime: Long = 0,
    
    /** 特殊交易額外負載 */
    val extraPayload: ByteArray = ByteArray(0)
) {
    init {
        require(inputs.isNotEmpty()) { "Transaction must have at least one input" }
        require(outputs.isNotEmpty()) { "Transaction must have at least one output" }
    }

    /**
     * 是否為特殊交易
     */
    fun isSpecialTransaction(): Boolean = type != DashTxType.STANDARD

    /**
     * 取得用於序列化的完整版本欄位
     * 版本 3+ 時，高 16 位元為類型
     */
    private fun getVersionForSerialization(): Int {
        return if (version >= 3 && type != DashTxType.STANDARD) {
            (type.value shl 16) or version
        } else {
            version
        }
    }

    /**
     * 計算 txid
     */
    val txid: TxId get() = TxId(doubleSha256(serialize()))

    /**
     * 序列化交易
     */
    fun serialize(): ByteArray {
        val buffer = ByteArrayBuilder()

        // Version (含類型)
        buffer.writeInt32LE(getVersionForSerialization())

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

        // LockTime
        buffer.writeInt32LE(lockTime.toInt())

        // Extra Payload (版本 3+ 的特殊交易)
        if (version >= 3 && isSpecialTransaction()) {
            buffer.writeVarInt(extraPayload.size.toLong())
            buffer.writeBytes(extraPayload)
        }

        return buffer.toByteArray()
    }

    /**
     * 計算簽名哈希 (與 Bitcoin 相同)
     */
    fun hashForSignature(
        inputIndex: Int,
        scriptCode: ByteArray,
        hashType: Int
    ): ByteArray {
        require(inputIndex in inputs.indices) { "Invalid input index" }

        val buffer = ByteArrayBuilder()
        buffer.writeInt32LE(getVersionForSerialization())
        buffer.writeVarInt(inputs.size.toLong())

        inputs.forEachIndexed { i, input ->
            buffer.writeBytes(input.previousTxHash)
            buffer.writeInt32LE(input.previousOutputIndex.toInt())
            
            if (i == inputIndex) {
                buffer.writeVarInt(scriptCode.size.toLong())
                buffer.writeBytes(scriptCode)
            } else {
                buffer.writeVarInt(0)
            }
            buffer.writeInt32LE(input.sequence.toInt())
        }

        buffer.writeVarInt(outputs.size.toLong())
        outputs.forEach { output ->
            buffer.writeInt64LE(output.value)
            buffer.writeVarInt(output.scriptPubKey.size.toLong())
            buffer.writeBytes(output.scriptPubKey)
        }

        buffer.writeInt32LE(lockTime.toInt())
        buffer.writeInt32LE(hashType)

        return doubleSha256(buffer.toByteArray())
    }

    private fun doubleSha256(data: ByteArray): ByteArray {
        return sha256(sha256(data))
    }

    private fun sha256(data: ByteArray): ByteArray {
        return Crypto.sha256(data)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        other as DashTransaction
        return version == other.version &&
                type == other.type &&
                inputs == other.inputs &&
                outputs == other.outputs &&
                lockTime == other.lockTime &&
                extraPayload.contentEquals(other.extraPayload)
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + type.hashCode()
        result = 31 * result + inputs.hashCode()
        result = 31 * result + outputs.hashCode()
        result = 31 * result + lockTime.hashCode()
        result = 31 * result + extraPayload.contentHashCode()
        return result
    }

    companion object {
        const val SIGHASH_ALL = 0x01
        
        /**
         * 從 Bitcoin Transaction 轉換
         */
        fun fromBitcoin(tx: Transaction): DashTransaction {
            return DashTransaction(
                version = 3,
                type = DashTxType.STANDARD,
                inputs = tx.inputs,
                outputs = tx.outputs,
                witnesses = tx.witnesses,
                lockTime = tx.lockTime
            )
        }

        /**
         * 反序列化
         */
        fun read(data: ByteArray): DashTransaction {
            val reader = ByteArrayReader(data)

            val versionFull = reader.readInt32LE()
            val version = versionFull and 0xFFFF
            val typeValue = (versionFull ushr 16) and 0xFFFF
            val type = if (version >= 3) DashTxType.fromValue(typeValue) else DashTxType.STANDARD

            val inputCount = reader.readVarInt()
            val inputs = (0 until inputCount).map { TxInput.read(reader) }

            val outputCount = reader.readVarInt()
            val outputs = (0 until outputCount).map { TxOutput.read(reader) }

            val lockTime = reader.readInt32LE().toLong() and 0xFFFFFFFFL

            val extraPayload = if (version >= 3 && type != DashTxType.STANDARD && reader.hasRemaining()) {
                val size = reader.readVarInt().toInt()
                reader.readBytes(size)
            } else {
                ByteArray(0)
            }

            return DashTransaction(
                version = version,
                type = type,
                inputs = inputs,
                outputs = outputs,
                lockTime = lockTime,
                extraPayload = extraPayload
            )
        }
    }
}

/**
 * Dash 交易建構器
 */
class DashTxBuilder {
    private var version: Int = 3
    private var type: DashTxType = DashTxType.STANDARD
    private val inputs = mutableListOf<TxInput>()
    private val outputs = mutableListOf<TxOutput>()
    private var lockTime: Long = 0
    private var extraPayload: ByteArray = ByteArray(0)

    fun version(version: Int) = apply { this.version = version }
    fun type(type: DashTxType) = apply { this.type = type }
    fun lockTime(lockTime: Long) = apply { this.lockTime = lockTime }
    fun extraPayload(payload: ByteArray) = apply { this.extraPayload = payload }

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

    fun build(): DashTransaction {
        require(inputs.isNotEmpty()) { "Must have at least one input" }
        require(outputs.isNotEmpty()) { "Must have at least one output" }

        return DashTransaction(
            version = version,
            type = type,
            inputs = inputs.toList(),
            outputs = outputs.toList(),
            lockTime = lockTime,
            extraPayload = extraPayload
        )
    }
}
