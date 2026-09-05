package io.github.iml1s.tx.ethereum

import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertTrue

class Eip1559ChainIdTest {

    @Test
    fun missingChainIdIsErrorNotMainnetFallback() {
        val tx = Eip1559Transaction(
            chainId = null,
            nonce = 0,
            maxPriorityFeePerGas = byteArrayOf(0x01),
            maxFeePerGas = byteArrayOf(0x02),
            gasLimit = 21000,
            to = "0x3535353535353535353535353535353535353535",
            value = byteArrayOf(0x01),
            data = byteArrayOf()
        )
        val ex = assertFails { tx.encode(forSigning = true) }
        assertTrue(ex.message!!.contains("chainId", ignoreCase = true))
    }
}
