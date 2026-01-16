package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.utils.Either
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test

class Musig2NonceDebugTest {
    @Test
    fun `debug nonce generation test case 1`() {
        // Test case 1 from nonce_gen_vectors.json
        val rand = Hex.decode("0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F")
        val sk = Hex.decode("0202020202020202020202020202020202020202020202020202020202020202")
        val pk = Hex.decode("024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766")
        val aggpk = Hex.decode("0707070707070707070707070707070707070707070707070707070707070707")
        val msg = Hex.decode("0101010101010101010101010101010101010101010101010101010101010101")
        val extraIn = Hex.decode("0808080808080808080808080808080808080808080808080808080808080808")
        
        val expectedPubnonce = "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A"
        val expectedSecnonce = "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766"
        
        // Build keyagg cache from aggpk
        val magic = Hex.decode("f4adbbdf")
        val keyaggCache = ByteArray(197)
        magic.copyInto(keyaggCache, 0)
        // Q is stored at offset 4 (32 bytes x-coord). The vector aggpk is 32 bytes 0x07...
        aggpk.copyInto(keyaggCache, 4)
        
        // Call musigNonceGen directly
        val nonce = Secp256k1.musigNonceGen(
            rand,
            sk,
            pk,
            msg,
            keyaggCache, // Pass the cache with aggpk
            extraIn
        )
        
        val secretNonce = nonce.copyOfRange(0, Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        val publicNonce = nonce.copyOfRange(Secp256k1.MUSIG2_SECRET_NONCE_SIZE, Secp256k1.MUSIG2_SECRET_NONCE_SIZE + Secp256k1.MUSIG2_PUBLIC_NONCE_SIZE)
        
        println("=== Nonce Generation Debug (Test Case 1 without keyagg) ===")
        println("Total nonce size: ${nonce.size}")
        println()
        println("Expected pubnonce: $expectedPubnonce")
        println("Actual pubnonce:   ${Hex.encode(publicNonce).uppercase()}")
        println()
        
        // Check if they match
        if (Hex.encode(publicNonce).uppercase() == expectedPubnonce) {
            println("✓ Public nonce matches!")
        } else {
            println("✗ Public nonce does NOT match!")
        }
        // Check if expected k produces expected R
        val ek1 = Hex.decode("B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB64")
        val ek2 = Hex.decode("95B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2")
        val eR1 = Secp256k1.pubkeyCreate(ek1)
        val eR2 = Secp256k1.pubkeyCreate(ek2)
        
        println("Expected R1 (from k1*G): ${Hex.encode(eR1)}")
        println("Expected R2 (from k2*G): ${Hex.encode(eR2)}")
        
        println("=== END DEBUG ===")
    }
}
