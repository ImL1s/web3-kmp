package io.github.iml1s.caip

import io.github.iml1s.caip.core.CAIPTransactionRequest
import io.github.iml1s.caip.model.CAIPAddress
import io.github.iml1s.caip.model.CAIPAsset
import io.github.iml1s.caip.model.CAIPChainID
import io.github.iml1s.caip.model.CAIPChainType
import io.github.iml1s.caip.model.CAIPResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CaipP1Test {

    private val eth = CAIPChainID.ETHEREUM_MAINNET
    private val good = CAIPAddress(eth, "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb")
    private val bad = CAIPAddress(eth, "not-an-address")
    private val asset = CAIPAsset.createNativeAsset(CAIPChainType.ETHEREUM)

    @Test
    fun successFalseIsNotValid() {
        // eip155 validate() returns Success(false) for a syntactically-parsed but invalid
        // address — not Failure. Ignoring the boolean (the audit defect) would treat
        // Success(false) as "validated" and return Success(true).
        assertNotAccepted(CAIPTransactionRequest(bad, good, asset, "1"))
        assertNotAccepted(CAIPTransactionRequest(good, bad, asset, "1"))
        assertNotAccepted(CAIPTransactionRequest(bad, bad, asset, "1"))
    }

    private fun assertNotAccepted(req: CAIPTransactionRequest) {
        val result = req.validate()
        val accepted = result is CAIPResult.Success && result.data == true
        assertFalse(accepted, "Success(false) address must not be treated as valid")
        if (result is CAIPResult.Success) {
            assertFalse(result.data)
        }
    }

    @Test
    fun nonFiniteAmountsRejected() {
        for (amount in listOf("NaN", "Infinity", "-Infinity", "1e309", "", " ")) {
            val req = CAIPTransactionRequest(good, good, asset, amount)
            val result = req.validate()
            assertTrue(result is CAIPResult.Failure, "amount $amount should fail")
        }
        val ok = CAIPTransactionRequest(good, good, asset, "1.5")
        assertEquals(true, (ok.validate() as CAIPResult.Success).data)
    }

    @Test
    fun emptyAccountRejected() {
        val parsed = CAIPAddress.parse("::")
        assertTrue(parsed is CAIPResult.Failure)
    }

    @Test
    fun nftAssetRoundTrip() {
        val nft = CAIPAsset.createNFTAsset(
            contractAddress = "0x06012c8cf97bead5deae237070f9587f8e7a266d",
            tokenId = "7",
            chainType = CAIPChainType.ETHEREUM
        )
        val encoded = nft.toCAIPString()
        assertEquals("eip155:1/erc721:0x06012c8cf97bead5deae237070f9587f8e7a266d/7", encoded)
        val parsed = CAIPAsset.parse(encoded)
        assertTrue(parsed is CAIPResult.Success)
        val data = (parsed as CAIPResult.Success).data
        assertEquals("7", data.tokenId)
        assertEquals(encoded, data.toCAIPString())
    }

    @Test
    fun unknownSolanaNetworkDoesNotDefaultToMainnet() {
        assertFails { CAIPChainID.fromChainType(CAIPChainType.SOLANA, "not-a-network") }
    }

    @Test
    fun unknownEthereumNetworkDoesNotDefaultToMainnet() {
        assertFails { CAIPChainID.fromChainType(CAIPChainType.ETHEREUM, "not-a-network") }
        val sepolia = CAIPChainID.fromChainType(CAIPChainType.ETHEREUM, "sepolia")
        assertEquals("eip155", sepolia.namespace)
        assertEquals("11155111", sepolia.reference)
        val mainnet = CAIPChainID.fromChainType(CAIPChainType.ETHEREUM, "mainnet")
        assertEquals("1", mainnet.reference)
    }
}
