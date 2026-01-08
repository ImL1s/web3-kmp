package io.github.iml1s.miniscript.node

import io.github.iml1s.miniscript.AbsLockTime
import io.github.iml1s.miniscript.Miniscript
import io.github.iml1s.miniscript.MiniscriptKey
import io.github.iml1s.miniscript.RelLockTime
import io.github.iml1s.miniscript.Threshold
import io.github.iml1s.miniscript.ToPublicKey
import io.github.iml1s.miniscript.context.ScriptContext

sealed class Terminal<Pk : MiniscriptKey, Ctx : ScriptContext> {
    abstract fun toScript(): List<ScriptElt>

    class True<Pk : MiniscriptKey, Ctx : ScriptContext> : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_1)
        override fun equals(other: Any?): Boolean = other is True<*, *>
        override fun hashCode(): Int = "True".hashCode()
        override fun toString(): String = "True"
    }

    class False<Pk : MiniscriptKey, Ctx : ScriptContext> : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_0)
        override fun equals(other: Any?): Boolean = other is False<*, *>
        override fun hashCode(): Int = "False".hashCode()
        override fun toString(): String = "False"
    }

    data class PkK<Pk : MiniscriptKey, Ctx : ScriptContext>(val pk: Pk) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val bytes = if (pk is ToPublicKey) pk.toPublicKey() else pk.toString().encodeToByteArray()
            return listOf(ScriptElt.Push(bytes))
        }
    }

    data class PkH<Pk : MiniscriptKey, Ctx : ScriptContext>(val pk: Pk) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val hash = if (pk is ToPublicKey) pk.toHash160(byteArrayOf()) /* placeholder */ else pk.toString().encodeToByteArray()
            return listOf(
                ScriptElt.OP_DUP,
                ScriptElt.OP_HASH160,
                ScriptElt.Push(hash),
                ScriptElt.OP_EQUALVERIFY,
                ScriptElt.OP_CHECKSIG
            )
        }
    }

    data class RawPkH<Pk : MiniscriptKey, Ctx : ScriptContext>(val hash: ByteArray) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.OP_DUP,
            ScriptElt.OP_HASH160,
            ScriptElt.Push(hash),
            ScriptElt.OP_EQUALVERIFY,
            ScriptElt.OP_CHECKSIG
        )
    }

    data class After<Pk : MiniscriptKey, Ctx : ScriptContext>(val value: AbsLockTime) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.Push(encodeNumber(value.toConsensusU32().toLong())),
            ScriptElt.OP_CHECKLOCKTIMEVERIFY
        )
    }

    data class Older<Pk : MiniscriptKey, Ctx : ScriptContext>(val value: RelLockTime) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.Push(encodeNumber(value.toConsensusU32().toLong())),
            ScriptElt.OP_CHECKSEQUENCEVERIFY
        )
    }

    data class Sha256<Pk : MiniscriptKey, Ctx : ScriptContext>(val hash: ByteArray) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.OP_SIZE, ScriptElt.fromInt(32), ScriptElt.OP_EQUALVERIFY,
            ScriptElt.OP_SHA256, ScriptElt.Push(hash), ScriptElt.OP_EQUAL
        )
    }

    data class Hash256<Pk : MiniscriptKey, Ctx : ScriptContext>(val hash: ByteArray) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.OP_SIZE, ScriptElt.fromInt(32), ScriptElt.OP_EQUALVERIFY,
            ScriptElt.OP_HASH256, ScriptElt.Push(hash), ScriptElt.OP_EQUAL
        )
    }

    data class Ripemd160<Pk : MiniscriptKey, Ctx : ScriptContext>(val hash: ByteArray) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.OP_SIZE, ScriptElt.fromInt(32), ScriptElt.OP_EQUALVERIFY,
            ScriptElt.OP_RIPEMD160, ScriptElt.Push(hash), ScriptElt.OP_EQUAL
        )
    }

    data class Hash160<Pk : MiniscriptKey, Ctx : ScriptContext>(val hash: ByteArray) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(
            ScriptElt.OP_SIZE, ScriptElt.fromInt(32), ScriptElt.OP_EQUALVERIFY,
            ScriptElt.OP_HASH160, ScriptElt.Push(hash), ScriptElt.OP_EQUAL
        )
    }

    data class Alt<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.Op(0x6b, "OP_TOALTSTACK")) + sub.node.toScript() + ScriptElt.Op(0x6c, "OP_FROMALTSTACK")
    }

    data class Swap<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_SWAP) + sub.node.toScript()
    }

    data class Check<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = sub.node.toScript() + ScriptElt.OP_CHECKSIG
    }

    data class DupIf<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_DUP, ScriptElt.OP_IF) + sub.node.toScript() + ScriptElt.OP_ENDIF
    }

    data class Verify<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val script = sub.node.toScript()
            val last = script.lastOrNull()
            return if (last is ScriptElt.Op) {
                val verifyOp = when (last) {
                    ScriptElt.OP_CHECKSIG -> ScriptElt.OP_CHECKSIGVERIFY
                    ScriptElt.OP_CHECKMULTISIG -> ScriptElt.OP_CHECKMULTISIGVERIFY
                    ScriptElt.OP_EQUAL -> ScriptElt.OP_EQUALVERIFY
                    ScriptElt.OP_NUMEQUAL -> ScriptElt.OP_NUMEQUALVERIFY
                    else -> null
                }
                if (verifyOp != null) {
                    script.dropLast(1) + verifyOp
                } else {
                    script + ScriptElt.OP_VERIFY
                }
            } else {
                script + ScriptElt.OP_VERIFY
            }
        }
    }

    data class NonZero<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_SIZE, ScriptElt.OP_0, ScriptElt.OP_0NOTEQUAL, ScriptElt.OP_IF) + sub.node.toScript() + ScriptElt.OP_ENDIF
    }

    data class ZeroNotEqual<Pk : MiniscriptKey, Ctx : ScriptContext>(val sub: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = sub.node.toScript() + ScriptElt.OP_0NOTEQUAL
    }

    data class AndV<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = l.node.toScript() + r.node.toScript()
    }

    data class AndB<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = l.node.toScript() + r.node.toScript() + ScriptElt.Op(0x9a, "OP_BOOLAND")
    }

    data class AndOr<Pk : MiniscriptKey, Ctx : ScriptContext>(val a: Miniscript<Pk, Ctx>, val b: Miniscript<Pk, Ctx>, val c: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = a.node.toScript() + listOf(ScriptElt.OP_NOTIF) + c.node.toScript() + listOf(ScriptElt.OP_ELSE) + b.node.toScript() + listOf(ScriptElt.OP_ENDIF)
    }
    
    data class OrB<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = l.node.toScript() + r.node.toScript() + ScriptElt.Op(0x9b, "OP_BOOLOR")
    }

    data class OrD<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = l.node.toScript() + listOf(ScriptElt.OP_IFDUP, ScriptElt.OP_NOTIF) + r.node.toScript() + listOf(ScriptElt.OP_ENDIF)
    }

    data class OrC<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = l.node.toScript() + listOf(ScriptElt.OP_NOTIF) + r.node.toScript() + listOf(ScriptElt.OP_ENDIF)
    }

    data class OrI<Pk : MiniscriptKey, Ctx : ScriptContext>(val l: Miniscript<Pk, Ctx>, val r: Miniscript<Pk, Ctx>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> = listOf(ScriptElt.OP_IF) + l.node.toScript() + listOf(ScriptElt.OP_ELSE) + r.node.toScript() + listOf(ScriptElt.OP_ENDIF)
    }

    data class Thresh<Pk : MiniscriptKey, Ctx : ScriptContext>(val thresh: Threshold<Miniscript<Pk, Ctx>>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val script = mutableListOf<ScriptElt>()
            script.addAll(thresh.data[0].node.toScript())
            for (i in 1 until thresh.data.size) {
                script.addAll(thresh.data[i].node.toScript())
                script.add(ScriptElt.OP_ADD)
            }
            script.add(ScriptElt.Push(encodeNumber(thresh.k.toLong())))
            script.add(ScriptElt.OP_EQUAL)
            return script
        }
    }

    data class Multi<Pk : MiniscriptKey, Ctx : ScriptContext>(val thresh: Threshold<Pk>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val script = mutableListOf<ScriptElt>()
            script.add(ScriptElt.fromInt(thresh.k))
            for (pk in thresh.data) {
                val bytes = if (pk is ToPublicKey) pk.toPublicKey() else pk.toString().encodeToByteArray()
                script.add(ScriptElt.Push(bytes))
            }
            script.add(ScriptElt.fromInt(thresh.data.size))
            script.add(ScriptElt.OP_CHECKMULTISIG)
            return script
        }
    }

    data class MultiA<Pk : MiniscriptKey, Ctx : ScriptContext>(val thresh: Threshold<Pk>) : Terminal<Pk, Ctx>() {
        override fun toScript(): List<ScriptElt> {
            val script = mutableListOf<ScriptElt>()
            val firstPk = thresh.data[0]
            val firstBytes = if (firstPk is ToPublicKey) firstPk.toPublicKey() else firstPk.toString().encodeToByteArray()
            script.add(ScriptElt.Push(firstBytes))
            script.add(ScriptElt.OP_CHECKSIG)
            for (i in 1 until thresh.data.size) {
                val pk = thresh.data[i]
                val bytes = if (pk is ToPublicKey) pk.toPublicKey() else pk.toString().encodeToByteArray()
                script.add(ScriptElt.Push(bytes))
                script.add(ScriptElt.OP_CHECKSIGADD)
            }
            script.add(ScriptElt.Push(encodeNumber(thresh.k.toLong())))
            script.add(ScriptElt.OP_NUMEQUAL)
            return script
        }
    }

    companion object {
        fun encodeNumber(value: Long): ByteArray {
            if (value == 0L) return byteArrayOf()
            val result = mutableListOf<Byte>()
            val neg = value < 0
            var absvalue = if (neg) -value else value
            while (absvalue > 0) {
                result.add((absvalue and 0xff).toByte())
                absvalue = absvalue shr 8
            }
            if ((result.last().toInt() and 0x80) != 0) {
                result.add(if (neg) 0x80.toByte() else 0)
            } else if (neg) {
                result[result.lastIndex] = (result[result.lastIndex].toInt() or 0x80).toByte()
            }
            return result.toByteArray()
        }
    }
}
