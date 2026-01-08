package io.github.iml1s.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * MuSig2 (BIP-327) Test Suite
 * 
 * Test vectors from: https://github.com/bitcoin/bips/tree/master/bip-0327/vectors
 */
class MuSig2Test {
    
    // ========================
    // BIP-327 Key Aggregation Vectors
    // ========================
    
    // Public keys from key_agg_vectors.json
    private val pubkeys = listOf(
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9"
    )
    
    @Test
    fun testKeyAggVector1() {
        // key_indices: [0, 1, 2]
        // expected: "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"
        val keys = listOf(
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[1]),
            Hex.decode(pubkeys[2])
        )
        
        val ctx = MuSig2.keyAgg(keys)
        val aggPk = MuSig2.getXonlyPk(ctx)
        
        assertEquals(
            "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C".lowercase(),
            Hex.encode(aggPk).lowercase()
        )
    }
    
    @Test
    fun testKeyAggVector2() {
        // key_indices: [2, 1, 0]
        // expected: "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"
        val keys = listOf(
            Hex.decode(pubkeys[2]),
            Hex.decode(pubkeys[1]),
            Hex.decode(pubkeys[0])
        )
        
        val ctx = MuSig2.keyAgg(keys)
        val aggPk = MuSig2.getXonlyPk(ctx)
        
        assertEquals(
            "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B".lowercase(),
            Hex.encode(aggPk).lowercase()
        )
    }
    
    @Test
    fun testKeyAggVector3_DuplicateKeys() {
        // key_indices: [0, 0, 0]
        // expected: "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"
        val keys = listOf(
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[0])
        )
        
        val ctx = MuSig2.keyAgg(keys)
        val aggPk = MuSig2.getXonlyPk(ctx)
        
        assertEquals(
            "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935".lowercase(),
            Hex.encode(aggPk).lowercase()
        )
    }
    
    @Test
    fun testKeyAggVector4_MixedDuplicates() {
        // key_indices: [0, 0, 1, 1]
        // expected: "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"
        val keys = listOf(
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[1]),
            Hex.decode(pubkeys[1])
        )
        
        val ctx = MuSig2.keyAgg(keys)
        val aggPk = MuSig2.getXonlyPk(ctx)
        
        assertEquals(
            "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E".lowercase(),
            Hex.encode(aggPk).lowercase()
        )
    }
    
    @Test
    fun testKeyAggError_InvalidPublicKey() {
        // key_indices: [0, 3] - key 3 has invalid x-coordinate
        val keys = listOf(
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[3])  // Invalid: 020000...0005
        )
        
        assertFailsWith<MuSig2.InvalidContributionError> {
            MuSig2.keyAgg(keys)
        }
    }
    
    @Test
    fun testKeyAggError_PublicKeyExceedsFieldSize() {
        // key_indices: [0, 4] - key 4 exceeds field size
        val keys = listOf(
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[4])  // Invalid: exceeds p
        )
        
        assertFailsWith<MuSig2.InvalidContributionError> {
            MuSig2.keyAgg(keys)
        }
    }
    
    @Test
    fun testKeyAggError_InvalidPrefix() {
        // key_indices: [5, 0] - key 5 has 0x04 prefix (uncompressed)
        val keys = listOf(
            Hex.decode(pubkeys[5]),  // Invalid: 0x04 prefix
            Hex.decode(pubkeys[0])
        )
        
        assertFailsWith<MuSig2.InvalidContributionError> {
            MuSig2.keyAgg(keys)
        }
    }
    
    // ========================
    // Tagged Hash Tests
    // ========================
    
    @Test
    fun testTaggedHash() {
        // BIP-340 challenge hash tag test
        val tag = "BIP0340/challenge"
        val msg = ByteArray(96) { 0x00 }
        
        val result = MuSig2.taggedHash(tag, msg)
        
        assertEquals(32, result.size, "Tagged hash should be 32 bytes")
    }
    
    // ========================
    // Key Sort Tests
    // ========================
    
    @Test
    fun testKeySort() {
        val keys = listOf(
            Hex.decode(pubkeys[2]),
            Hex.decode(pubkeys[0]),
            Hex.decode(pubkeys[1])
        )
        
        val sorted = MuSig2.keySort(keys)
        
        // Should be sorted lexicographically (0x02... before 0x03...)
        assertEquals(Hex.encode(sorted[0]).substring(0, 2), "02")
        assertEquals(Hex.encode(sorted[1]).substring(0, 2), "02")
        assertEquals(Hex.encode(sorted[2]).substring(0, 2), "03")
    }
    
    // ========================
    // Individual Public Key Tests
    // ========================
    
    @Test
    fun testIndividualPk() {
        // Known test vector: secret key 1 should give generator point
        val sk = ByteArray(32) { 0 }
        sk[31] = 0x01
        
        val pk = MuSig2.individualPk(sk)
        
        assertEquals(33, pk.size, "Compressed pubkey should be 33 bytes")
        // Generator point x-coordinate starts with 79BE...
        assertEquals(
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798".lowercase(),
            Hex.encode(pk.copyOfRange(1, 33)).lowercase()
        )
    }
    
    // ========================
    // Nonce Generation Tests
    // ========================
    
    @Test
    fun testNonceGen() {
        val sk = Hex.decode("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D74E5E3B7B10")
        val pk = MuSig2.individualPk(sk)
        
        val (secnonce, pubnonce) = MuSig2.nonceGen(sk = sk, pk = pk)
        
        assertEquals(97, secnonce.size, "secnonce should be 97 bytes (k1 + k2 + pk)")
        assertEquals(66, pubnonce.size, "pubnonce should be 66 bytes (R1 + R2)")
    }
    
    // ========================
    // Nonce Aggregation Tests
    // ========================
    
    @Test
    fun testNonceAgg() {
        val sk1 = Hex.decode("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D74E5E3B7B10")
        val sk2 = Hex.decode("3CB41E6B5A2BE853ED5EA5E5E3B1CF0BE3B3D0D16B8D5E5A6E9E9B1C0A0B0C0D")
        
        val pk1 = MuSig2.individualPk(sk1)
        val pk2 = MuSig2.individualPk(sk2)
        
        val (_, pubnonce1) = MuSig2.nonceGen(sk = sk1, pk = pk1)
        val (_, pubnonce2) = MuSig2.nonceGen(sk = sk2, pk = pk2)
        
        val aggnonce = MuSig2.nonceAgg(listOf(pubnonce1, pubnonce2))
        
        assertEquals(66, aggnonce.size, "aggnonce should be 66 bytes")
    }
    
    // ========================
    // Full Signing Flow Test
    // ========================
    
    @Test
    fun testFullSigningFlow() {
        // Two signers: Alice and Bob
        val aliceSk = Hex.decode("7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D74E5E3B7B10")
        val bobSk = Hex.decode("3CB41E6B5A2BE853ED5EA5E5E3B1CF0BE3B3D0D16B8D5E5A6E9E9B1C0A0B0C0D")
        
        val alicePk = MuSig2.individualPk(aliceSk)
        val bobPk = MuSig2.individualPk(bobSk)
        
        val pubkeys = listOf(alicePk, bobPk)
        val sortedPubkeys = MuSig2.keySort(pubkeys)
        
        // Key Aggregation
        val keyAggCtx = MuSig2.keyAgg(sortedPubkeys)
        val aggPk = MuSig2.getXonlyPk(keyAggCtx)
        
        // Message to sign
        val msg = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        
        // Nonce Generation (Round 1)
        val (aliceSecnonce, alicePubnonce) = MuSig2.nonceGen(sk = aliceSk, pk = alicePk, aggpk = aggPk, msg = msg)
        val (bobSecnonce, bobPubnonce) = MuSig2.nonceGen(sk = bobSk, pk = bobPk, aggpk = aggPk, msg = msg)
        
        // Nonce Aggregation
        val aggnonce = MuSig2.nonceAgg(listOf(alicePubnonce, bobPubnonce))
        
        // Session Context
        val sessionCtx = MuSig2.SessionContext(
            aggnonce = aggnonce,
            pubkeys = sortedPubkeys,
            tweaks = emptyList(),
            isXonly = emptyList(),
            msg = msg
        )
        
        // Signing (Round 2)
        val alicePsig = MuSig2.sign(aliceSecnonce, aliceSk, sessionCtx)
        val bobPsig = MuSig2.sign(bobSecnonce, bobSk, sessionCtx)
        
        // Signature Aggregation
        val sig = MuSig2.partialSigAgg(listOf(alicePsig, bobPsig), sessionCtx)
        
        assertEquals(64, sig.size, "Final signature should be 64 bytes")
        
        // Verify the signature
        val valid = MuSig2.schnorrVerify(msg, aggPk, sig)
        assertEquals(true, valid, "Signature should be valid")
    }
    
    // ========================
    // Schnorr Verification Test
    // ========================
    
    @Test
    fun testSchnorrVerify_ValidSignature() {
        // BIP-340 Test Vector 0
        val pk = Hex.decode("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        val msg = Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")
        val sig = Hex.decode("E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        
        val valid = MuSig2.schnorrVerify(msg, pk, sig)
        assertEquals(true, valid, "BIP-340 Vector 0 should be valid")
    }
}
