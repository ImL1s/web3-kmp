package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.PublicKey
import fr.acinq.bitcoin.XonlyPublicKey
import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertEquals

class Musig2DebugTest {
    @Test
    fun `debug key aggregation test case 0`() {
        // Test vector keys
        val pk0 = PublicKey(Hex.decode("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"))
        val pk1 = PublicKey(Hex.decode("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"))
        val pk2 = PublicKey(Hex.decode("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66"))
        
        // Expected result for [0, 1, 2] from official BIP-327 test vectors
        // Source: musig2/key_agg_vectors.json valid_test_cases[0]
        val expectedHex = "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"
        
        // Test
        val (aggkey, _) = KeyAggCache.create(listOf(pk0, pk1, pk2))
        
        println("Expected: $expectedHex")
        println("Got:      ${aggkey.value.toHex()}")
        
        assertEquals(expectedHex.lowercase(), aggkey.value.toHex().lowercase())
    }
}
