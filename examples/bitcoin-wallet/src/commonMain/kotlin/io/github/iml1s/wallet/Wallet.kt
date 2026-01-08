package io.github.iml1s.wallet

import io.github.iml1s.client.BlockchainClient
import io.github.iml1s.client.ChainUTXO
import io.github.iml1s.utxo.CoinSelector
import io.github.iml1s.utxo.SelectionStrategy

/**
 * A simple Bitcoin Wallet demonstration using web3-kmp modules.
 *
 * This wallet demonstrates:
 * - UTXO fetching from blockchain
 * - Coin selection for transaction building
 *
 * Note: Full HD key derivation requires crypto-pure integration (TBD).
 */
class Wallet(
    private val client: BlockchainClient,
    private val network: Network = Network.MAINNET
) {
    /**
     * Network configuration
     */
    enum class Network(val coinType: Int) {
        MAINNET(0),
        TESTNET(1)
    }

    /**
     * Get balance for a specific address.
     */
    suspend fun getBalance(address: String): Long {
        return client.getBalance(address)
    }

    /**
     * Fetch all UTXOs for a given address.
     */
    suspend fun getUTXOs(address: String): List<ChainUTXO> {
        return client.getUTXOs(address)
    }

    /**
     * Get recommended fee rates.
     */
    suspend fun getFeeRates() = client.getFeeRates()

    /**
     * Select UTXOs for a given target amount.
     */
    fun selectCoins(
        utxos: List<ChainUTXO>,
        targetAmount: Long,
        feeRate: Long,
        strategy: SelectionStrategy = SelectionStrategy.LARGEST_FIRST
    ): CoinSelector.SelectionResult {
        return CoinSelector.select(
            utxos = utxos.map { io.github.iml1s.utxo.UTXO(it.txid, it.vout, it.value, confirmed = true) },
            targetAmount = targetAmount,
            feeRate = feeRate,
            strategy = strategy
        )
    }

    /**
     * Broadcast a signed transaction.
     */
    suspend fun broadcast(rawTxHex: String): String {
        return client.broadcastTransaction(rawTxHex)
    }
}
