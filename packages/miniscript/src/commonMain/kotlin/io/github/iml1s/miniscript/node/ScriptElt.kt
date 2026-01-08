package io.github.iml1s.miniscript.node

/**
 * A minimal representation of a Bitcoin Script element (Opcode or PushData).
 */
sealed class ScriptElt {
    abstract val code: Int

    data class Op(override val code: Int, val name: String) : ScriptElt() {
        override fun toString(): String = name
    }

    data class Push(val data: ByteArray) : ScriptElt() {
        override val code: Int
            get() = when {
                data.size < 0x4c -> data.size
                data.size <= 0xff -> 0x4c
                data.size <= 0xffff -> 0x4d
                else -> 0x4e
            }

        override fun toString(): String = "Push(${data.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }})"
        
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Push) return false
            return data.contentEquals(other.data)
        }

        override fun hashCode(): Int = data.contentHashCode()
    }

    data class RawBytes(val bytes: ByteArray) : ScriptElt() {
        override val code: Int = -1
        override fun toString(): String = "RawBytes(${bytes.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RawBytes) return false
            return bytes.contentEquals(other.bytes)
        }
        override fun hashCode(): Int = bytes.contentHashCode()
    }

    companion object {
        val OP_0 = Op(0x00, "OP_0")
        val OP_PUSHDATA1 = Op(0x4c, "OP_PUSHDATA1")
        val OP_PUSHDATA2 = Op(0x4d, "OP_PUSHDATA2")
        val OP_PUSHDATA4 = Op(0x4e, "OP_PUSHDATA4")
        val OP_1NEGATE = Op(0x4f, "OP_1NEGATE")
        val OP_1 = Op(0x51, "OP_1")
        val OP_2 = Op(0x52, "OP_2")
        val OP_3 = Op(0x53, "OP_3")
        val OP_4 = Op(0x54, "OP_4")
        val OP_5 = Op(0x55, "OP_5")
        val OP_6 = Op(0x56, "OP_6")
        val OP_7 = Op(0x57, "OP_7")
        val OP_8 = Op(0x58, "OP_8")
        val OP_9 = Op(0x59, "OP_9")
        val OP_10 = Op(0x5a, "OP_10")
        val OP_11 = Op(0x5b, "OP_11")
        val OP_12 = Op(0x5c, "OP_12")
        val OP_13 = Op(0x5d, "OP_13")
        val OP_14 = Op(0x5e, "OP_14")
        val OP_15 = Op(0x5f, "OP_15")
        val OP_16 = Op(0x60, "OP_16")

        val OP_IF = Op(0x63, "OP_IF")
        val OP_NOTIF = Op(0x64, "OP_NOTIF")
        val OP_ELSE = Op(0x67, "OP_ELSE")
        val OP_ENDIF = Op(0x68, "OP_ENDIF")
        val OP_VERIFY = Op(0x69, "OP_VERIFY")
        val OP_RETURN = Op(0x6a, "OP_RETURN")
        val OP_DUP = Op(0x76, "OP_DUP")
        val OP_IFDUP = Op(0x73, "OP_IFDUP")
        val OP_SWAP = Op(0x7c, "OP_SWAP")
        val OP_EQUAL = Op(0x87, "OP_EQUAL")
        val OP_EQUALVERIFY = Op(0x88, "OP_EQUALVERIFY")
        val OP_0NOTEQUAL = Op(0x92, "OP_0NOTEQUAL")
        val OP_ADD = Op(0x93, "OP_ADD")
        val OP_NUMEQUAL = Op(0x9c, "OP_NUMEQUAL")
        val OP_NUMEQUALVERIFY = Op(0x9d, "OP_NUMEQUALVERIFY")
        
        val OP_RIPEMD160 = Op(0xa6, "OP_RIPEMD160")
        val OP_SHA256 = Op(0xa8, "OP_SHA256")
        val OP_HASH160 = Op(0xa9, "OP_HASH160")
        val OP_HASH256 = Op(0xaa, "OP_HASH256")
        
        val OP_CHECKSIG = Op(0xac, "OP_CHECKSIG")
        val OP_CHECKSIGVERIFY = Op(0xad, "OP_CHECKSIGVERIFY")
        val OP_CHECKMULTISIG = Op(0xae, "OP_CHECKMULTISIG")
        val OP_CHECKMULTISIGVERIFY = Op(0xaf, "OP_CHECKMULTISIGVERIFY")
        
        val OP_CHECKLOCKTIMEVERIFY = Op(0xb1, "OP_CHECKLOCKTIMEVERIFY")
        val OP_CHECKSEQUENCEVERIFY = Op(0xb2, "OP_CHECKSEQUENCEVERIFY")
        val OP_DROP = Op(0x75, "OP_DROP")
        val OP_SIZE = Op(0x82, "OP_SIZE")

        // BIP 342
        val OP_CHECKSIGADD = Op(0xba, "OP_CHECKSIGADD")

        fun fromInt(n: Int): ScriptElt {
            return when (n) {
                0 -> OP_0
                -1 -> OP_1NEGATE
                in 1..16 -> fromOpCode(0x50 + n)
                else -> Push(encodeScriptInt(n.toLong()))
            }
        }

        private fun encodeScriptInt(v: Long): ByteArray {
             if (v == 0L) return ByteArray(0)
             var result = ArrayList<Byte>()
             var value = kotlin.math.abs(v)
             val neg = v < 0
             while (value > 0) {
                 result.add((value and 0xff).toByte())
                 value = value shr 8
             }
             // If sign bit is set, we need another byte
             if ((result.last().toInt() and 0x80) != 0) {
                 if (neg) {
                     result.add(0x80.toByte())
                 } else {
                     result.add(0x00)
                 }
             } else if (neg) {
                 result[result.size - 1] = (result[result.size - 1].toInt() or 0x80).toByte()
             }
             return result.toByteArray()
        }

        private fun fromOpCode(code: Int): ScriptElt {
            // Simplified mapping
            return when (code) {
                0x00 -> OP_0
                0x51 -> OP_1
                0x52 -> OP_2
                0x53 -> OP_3
                0x54 -> OP_4
                0x55 -> OP_5
                0x56 -> OP_6
                0x57 -> OP_7
                0x58 -> OP_8
                0x59 -> OP_9
                0x5a -> OP_10
                0x5b -> OP_11
                0x5c -> OP_12
                0x5d -> OP_13
                0x5e -> OP_14
                0x5f -> OP_15
                0x60 -> OP_16
                else -> Op(code, "OP_UNKNOWN_$code")
            }
        }
    }
}
