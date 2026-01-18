package fr.acinq.bitcoin

import fr.acinq.bitcoin.*
import fr.acinq.secp256k1.Hex
import kotlin.test.Test

class OpCountTest {

    @Test
    fun testOpCount() {
        val longScript = "10 10 " + (1..150).joinToString(" ") { "TOALTSTACK FROMALTSTACK" }
        // We use a different massive script for the second set of tests, matching what was in the original file but generated
        val massiveScript = "1 1 0 IF NOP VER ELSE 1 NOTIF VERIFY RETURN TOALTSTACK FROMALTSTACK 2DROP 2DUP 3DUP 2OVER 2ROT 2SWAP IFDUP DEPTH DROP DUP NIP OVER PICK ROLL ROT SWAP TUCK SIZE EQUAL EQUALVERIFY RESERVED1 RESERVED2 1ADD 1SUB NEGATE ABS NOT 0NOTEQUAL ADD SUB BOOLAND BOOLOR NUMEQUAL NUMEQUALVERIFY NUMNOTEQUAL LESSTHAN GREATERTHAN LESSTHANOREQUAL MIN MAX WITHIN RIPEMD160 SHA1 SHA256 HASH160 HASH256 CODESEPARATOR CHECKSIG CHECKSIGVERIFY CHECKMULTISIG CHECKMULTISIGVERIFY NOP1 CHECKLOCKTIMEVERIFY CHECKSEQUENCEVERIFY NOP4 NOP5 NOP6 NOP7 NOP8 NOP9 NOP10 CHECKSIGADD " +
            (1..100).joinToString(" ") { "VER" } + " ENDIF ENDIF" 

        val cases = listOf(
            Triple(
                longScript,
                "ADD 20 EQUAL",
                "Line 68 (OK)"
            ),
            Triple(
                longScript,
                "ADD 20 EQUAL",
                "Line 69 (TOO_MANY_OPS)"
            ),
            Triple(
                massiveScript,
                "",
                "Line 72 (TOO_MANY_OPS)"
            )
        )

        cases.forEach { (ssigText, spubText, label) ->
            println("--- Testing $label ---")
            val ssig = parseFromText(ssigText)
            val spub = parseFromText(spubText)
            
            val tx = Transaction(
                version = 1,
                txIn = listOf(TxIn(OutPoint(TxHash(ByteArray(32)), 0), ssig, 0xffffffff)),
                txOut = listOf(TxOut(Satoshi(0), ByteArray(0))),
                lockTime = 0
            )
            val ctx = Script.Context(tx, 0, Satoshi(0), listOf())
            val runner = Script.Runner(ctx, ScriptFlags.MANDATORY_SCRIPT_VERIFY_FLAGS)
            
            try {
                val result = runner.verifyScripts(ssig, spub, ScriptWitness.empty)
                println("Result: $result")
            } catch (t: Throwable) {
                println("Failed with: ${t.message}")
            }
        }
    }

    private fun parseFromText(input: String): ByteArray {
        fun parseInternal(tokens: List<String>, acc: ByteArray = ByteArray(0)): ByteArray {
            return if (tokens.isEmpty()) acc else {
                val head = tokens.first()
                val tail = tokens.drop(1)
                when {
                    head.matches(Regex("^-?[0-9]*$")) -> {
                        when {
                            head.toLong() == -1L -> parseInternal(tail, acc + OP_1NEGATE.code.toByte())
                            head.toLong() == 0L -> parseInternal(tail, acc + OP_0.code.toByte())
                            head.toLong() in 1..16 -> {
                                val byte = (OP_1.code - 1 + head.toInt()).toByte()
                                val bytes = arrayOf(byte).toByteArray()
                                parseInternal(tail, acc + bytes)
                            }
                            else -> {
                                val bytes = Script.encodeNumber(head.toLong())
                                parseInternal(tail, acc + Script.write(listOf(OP_PUSHDATA(bytes))))
                            }
                        }
                    }
                    ScriptEltMapping.name2code.containsKey(head) -> parseInternal(tail, acc + ScriptEltMapping.name2code.getValue(head).toByte())
                    head.startsWith("0x") -> parseInternal(tail, acc + Hex.decode(head.removePrefix("0x")))
                    else -> throw IllegalArgumentException("cannot parse $head")
                }
            }
        }

        val tokens = input.split(' ').filterNot { it.isEmpty() }.map { it.removePrefix("OP_") }.toList()
        return parseInternal(tokens)
    }
}
