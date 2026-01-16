package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.crypto.musig2.*
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Musig2TraceTest {
    fun String.decodeHex() = Hex.decode(this)

    @Test
    fun traceSignVector() {
        // BIP-327 sign_verify_vectors.json Case 0
        val sk = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671".decodeHex()
        val pks = listOf(
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9".decodeHex(),
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".decodeHex(),
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661".decodeHex()
        )
        val aggnonce = AggregatedNonce("0337c87821afd50a8644d820a8f3e02e499c931865c2360fb43d0a0d20dafe07ea0287bf891d2a6deaebadc909352aa9405d1428c15f4b75f04dae642a95c2548480".decodeHex())
        val msg = "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF".decodeHex()
        val expected = "f8a33dfe47c4182316bfbcd5deef2ca3e01900c91a2eb69efea758990420e761".decodeHex()
        
        val (aggpub, keyaggCache) = KeyAggCache.create(pks.map { PublicKey(it) })
        val session = Session.create(aggnonce, ByteVector32(msg), keyaggCache)
        
        // Signer 0 secnonce from vectors[0]
        val k1 = "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61".decodeHex()
        val k2 = "FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F7".decodeHex()
        
        val pk = pks[0]
        val pkPair = Secp256k1.pubkeyParse(pk)
        // Secp256k1.pubkeyParse returns big-endian px, py (65 bytes total: 04 || px || py).
        val px = pkPair.sliceArray(1..32).reversedArray()
        val py = pkPair.sliceArray(33..64).reversedArray()
        val magic = byteArrayOf(0x22, 0x0E, 0xDC.toByte(), 0xF1.toByte())
        val secnonceBytes = magic + k1 + k2 + px + py
        
        val psig = session.sign(SecretNonce(secnonceBytes), PrivateKey(sk))
        
        println("DEBUG TEST traceSign: psig=${psig.toHex()}")
        assertEquals(expected.byteVector32(), ByteVector32(psig))
        assertTrue(session.verify(psig, IndividualNonce(aggnonce.toByteArray().sliceArray(0..65)), PublicKey(pks[0])))
    }
    @Test
    fun traceSignVectorCase0Repro() {
        // Reproduction of failures in Musig2TestsCommon key_indices [0,1,2], aggNonce 028465FC...
        val sk = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671".decodeHex() 
        val pks = listOf(
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9".decodeHex(),
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9".decodeHex(),
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659".decodeHex()
        )
        // aggnonce from json line 18 (index 0)
        val aggnonce = AggregatedNonce("028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9".decodeHex())
        val msg = "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF".decodeHex()
        
        // Expected from json updated case 0
        val expected = "43a49d78d16a7b414af8ab70caf26208db597f620b6af00ba2403eef999c71a3".decodeHex()
        
        val (_, keyaggCache) = KeyAggCache.create(pks.map { PublicKey(it) })
        
        val session = Session.create(aggnonce, ByteVector32(msg), keyaggCache)
        
        // Secnonce from json line 9 (same as before)
        val k1 = "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61".decodeHex()
        val k2 = "FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F7".decodeHex()
        
        val pk = pks[0]
        val pkPair = Secp256k1.pubkeyParse(pk)
        val px = pkPair.sliceArray(1..32).reversedArray()
        val py = pkPair.sliceArray(33..64).reversedArray()
        val magic = byteArrayOf(0x22, 0x0E, 0xDC.toByte(), 0xF1.toByte())
        val secnonceBytes = magic + k1 + k2 + px + py
        
        val psig = session.sign(SecretNonce(secnonceBytes), PrivateKey(sk))
        
        println("DEBUG REPRO SIGN: psig=${psig.toHex()}")
        assertEquals(expected.byteVector32(), ByteVector32(psig))
    }
}
