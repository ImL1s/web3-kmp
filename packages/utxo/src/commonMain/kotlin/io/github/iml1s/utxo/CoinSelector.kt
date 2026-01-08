package io.github.iml1s.utxo

/**
 * Coin selection strategy for UTXO-based transactions.
 */
enum class SelectionStrategy {
    /** Select largest UTXOs first to minimize number of inputs */
    LARGEST_FIRST,
    /** Select smallest UTXOs first to consolidate dust */
    SMALLEST_FIRST,
    /** Branch and Bound for optimal selection (minimizes change) */
    BRANCH_AND_BOUND
}

/**
 * Coin Selector for choosing UTXOs to fund a transaction.
 *
 * Implements multiple strategies following Bitcoin Core's approach.
 */
object CoinSelector {

    /**
     * Estimated input size for P2WPKH (native segwit) in vbytes.
     * Real size: ~68 vbytes (witness discounted)
     */
    const val P2WPKH_INPUT_SIZE = 68

    /**
     * Estimated output size for P2WPKH in bytes.
     */
    const val P2WPKH_OUTPUT_SIZE = 31

    /**
     * Base transaction overhead (version, locktime, segwit marker, etc.)
     */
    const val TX_OVERHEAD = 11

    /**
     * Result of coin selection.
     */
    data class SelectionResult(
        val selectedUtxos: List<UTXO>,
        val totalSelected: Long,
        val fee: Long,
        val change: Long
    ) {
        val isSuccess: Boolean get() = selectedUtxos.isNotEmpty() && change >= 0
    }

    /**
     * Select UTXOs to fund a transaction.
     *
     * @param utxos Available UTXOs
     * @param targetAmount Amount to send (satoshis)
     * @param feeRate Fee rate in sat/vB
     * @param strategy Selection strategy
     * @return SelectionResult with chosen UTXOs or empty if insufficient funds
     */
    fun select(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long,
        strategy: SelectionStrategy = SelectionStrategy.LARGEST_FIRST
    ): SelectionResult {
        if (utxos.isEmpty()) {
            return SelectionResult(emptyList(), 0, 0, -1)
        }

        return when (strategy) {
            SelectionStrategy.LARGEST_FIRST -> selectLargestFirst(utxos, targetAmount, feeRate)
            SelectionStrategy.SMALLEST_FIRST -> selectSmallestFirst(utxos, targetAmount, feeRate)
            SelectionStrategy.BRANCH_AND_BOUND -> selectBranchAndBound(utxos, targetAmount, feeRate)
        }
    }

    private fun selectLargestFirst(utxos: List<UTXO>, targetAmount: Long, feeRate: Long): SelectionResult {
        val sorted = utxos.sortedByDescending { it.value }
        return selectGreedy(sorted, targetAmount, feeRate)
    }

    private fun selectSmallestFirst(utxos: List<UTXO>, targetAmount: Long, feeRate: Long): SelectionResult {
        val sorted = utxos.sortedBy { it.value }
        return selectGreedy(sorted, targetAmount, feeRate)
    }

    private fun selectGreedy(sortedUtxos: List<UTXO>, targetAmount: Long, feeRate: Long): SelectionResult {
        val selected = mutableListOf<UTXO>()
        var totalSelected = 0L

        for (utxo in sortedUtxos) {
            selected.add(utxo)
            totalSelected += utxo.value

            val fee = estimateFee(selected.size, 2, feeRate) // Assume 2 outputs (recipient + change)
            val change = totalSelected - targetAmount - fee

            if (change >= 0) {
                return SelectionResult(selected, totalSelected, fee, change)
            }
        }

        // Insufficient funds
        val fee = estimateFee(selected.size, 2, feeRate)
        return SelectionResult(selected, totalSelected, fee, totalSelected - targetAmount - fee)
    }

    /**
     * Branch and Bound coin selection (simplified).
     * Tries to find a selection that exactly matches target + fee (no change).
     */
    private fun selectBranchAndBound(utxos: List<UTXO>, targetAmount: Long, feeRate: Long): SelectionResult {
        // Simplified: Fall back to largest-first, but try to find exact match first
        val sorted = utxos.sortedByDescending { it.value }

        // Try exact match (no change output, so only 1 output)
        for (i in sorted.indices) {
            val subset = sorted.take(i + 1)
            val total = subset.sumOf { it.value }
            val fee = estimateFee(subset.size, 1, feeRate)
            val overage = total - targetAmount - fee

            // Accept if exact or very small overage (dust threshold ~546 sats)
            if (overage in 0..546) {
                return SelectionResult(subset, total, fee + overage, 0)
            }
        }

        // Fall back to greedy with change
        return selectLargestFirst(utxos, targetAmount, feeRate)
    }

    /**
     * Estimate transaction fee in satoshis.
     */
    fun estimateFee(inputCount: Int, outputCount: Int, feeRate: Long): Long {
        val vsize = TX_OVERHEAD + (inputCount * P2WPKH_INPUT_SIZE) + (outputCount * P2WPKH_OUTPUT_SIZE)
        return vsize * feeRate
    }
}
