package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.json.*
import kotlin.test.*

class Musig2SignDebugTest {
    @Test
    fun debugSign() {
        val tests = TestHelpers.readResourceAsJson("musig2/sign_verify_vectors.json")
        val privateKey = PrivateKey.fromHex(tests.jsonObject["sk"]!!.jsonPrimitive.content)
        val pubkeysGlobal = tests.jsonObject["pubkeys"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val secnoncesGlobal = tests.jsonObject["secnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val aggnoncesGlobal = tests.jsonObject["aggnonces"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }
        val msgsGlobal = tests.jsonObject["msgs"]!!.jsonArray.map { Hex.decode(it.jsonPrimitive.content) }

        tests.jsonObject["valid_test_cases"]!!.jsonArray.forEachIndexed { index, it ->
            println("=== Test Case $index ===")
            val keyIndices = it.jsonObject["key_indices"]!!.jsonArray.map { it.jsonPrimitive.int }
            val aggnonceIndex = it.jsonObject["aggnonce_index"]!!.jsonPrimitive.int
            val msgIndex = it.jsonObject["msg_index"]!!.jsonPrimitive.int
            val expectedSig = ByteVector32.fromValidHex(it.jsonObject["expected"]!!.jsonPrimitive.content)
            
            val secnonceIndex = 0 
            val signerIndex = it.jsonObject["signer_index"]!!.jsonPrimitive.int
            val myKeyIndex = keyIndices[signerIndex]
            
            val pubkeys = keyIndices.map { PublicKey(ByteVector(pubkeysGlobal[it])) }
            val aggnonce = aggnoncesGlobal[aggnonceIndex]
            val msg = msgsGlobal[msgIndex]

            // Setup cache
            try {
                val (aggKey, cache) = KeyAggCache.create(pubkeys)
                
                // Setup nonce
                val secnonceRaw = secnoncesGlobal[secnonceIndex] 
                
                val k1 = secnonceRaw.sliceArray(0 until 32)
                val k2 = secnonceRaw.sliceArray(32 until 64)
                val pkCompressed = secnonceRaw.sliceArray(64 until 97)
                 val (pk_x, pk_y) = fr.acinq.secp256k1.Secp256k1.pubkeyParse(pkCompressed).let { 
                   val x = it.sliceArray(1 until 33)
                   val y = it.sliceArray(33 until 65)
                   // Secnonce stores public key coordinates in Little Endian?
                   // musigNonceGen in Secp256k1Pure reverses them before storing.
                   // musigNonceValidate reads them as LE (via reverse() back to BE for comparison if stored as LE?).
                   // Wait, musigNonceValidate reads bytes, calls reverse() on them, then compares with X/Y from pubkeyParse (BE).
                   // So it expects stored bytes to be LE.
                   x.reverse()
                   y.reverse()
                   Pair(x, y)
                }
                val magicBytes = Hex.decode("40707328")
                val secnonce = magicBytes + k1 + k2 + pk_x + pk_y
                val secretNonceObj = SecretNonce(ByteVector(secnonce))
                
                // Process session
                val session = Secp256k1.musigNonceProcess(aggnonce, msg, cache.toByteArray())
                println("Session: ${Hex.encode(session)}")
                
                val partialSig = Secp256k1.musigPartialSign(secretNonceObj.data.toByteArray(), privateKey.value.toByteArray(), cache.toByteArray(), session)
                println("Partial Sig: ${Hex.encode(partialSig)}")
                println("Expected    : ${expectedSig.toHex()}")
                
                if (Hex.encode(partialSig) != expectedSig.toHex()) {
                    println("MISMATCH!")
                } else {
                    println("MATCH!")
                }
            } catch (e: Exception) {
                println("FAILED with error: ${e.message}")
                e.printStackTrace()
            }
        }
    }
}
