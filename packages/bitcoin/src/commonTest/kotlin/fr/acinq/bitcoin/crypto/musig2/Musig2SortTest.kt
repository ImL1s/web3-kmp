package fr.acinq.bitcoin.crypto.musig2

import fr.acinq.secp256k1.Hex
import kotlin.test.Test

class Musig2SortTest {
    @Test
    fun `test public key sorting`() {
        val pk0 = Hex.decode("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        val pk1 = Hex.decode("03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
        val pk2 = Hex.decode("023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66")
        
        val keys = listOf(pk0, pk1, pk2)
        
        val sorted = keys.sortedWith(Comparator { a, b ->
            for (i in 0 until minOf(a.size, b.size)) {
                val v1 = a[i].toInt() and 0xFF
                val v2 = b[i].toInt() and 0xFF
                if (v1 != v2) return@Comparator v1 - v2
            }
            a.size - b.size
        })
        
        println("Original order:")
        println("pk0: ${Hex.encode(pk0)}")
        println("pk1: ${Hex.encode(pk1)}")
        println("pk2: ${Hex.encode(pk2)}")
        
        println("\nSorted order:")
        sorted.forEachIndexed { i, pk ->
            println("$i: ${Hex.encode(pk)}")
        }
        
        println("\nExpected order for test [0,1,2]:")
        println("Should be: pk0, pk1, pk2")
    }
}
