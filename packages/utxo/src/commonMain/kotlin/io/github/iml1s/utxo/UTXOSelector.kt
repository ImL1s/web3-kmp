package io.github.iml1s.utxo

import kotlin.random.Random

/**
 * UTXO Selector - Implements multiple UTXO selection algorithms for Bitcoin transactions.
 *
 * This class provides various strategies for selecting which UTXOs to use as inputs
 * when constructing a Bitcoin transaction. The goal is to select UTXOs that:
 * 1. Cover the target amount plus fees
 * 2. Minimize transaction fees where possible
 * 3. Handle change outputs appropriately
 *
 * Usage:
 * ```kotlin
 * val selector = UTXOSelector()
 * val selection = selector.select(
 *     utxos = availableUTXOs,
 *     targetAmount = 100_000, // satoshis
 *     feeRate = 10 // sat/vB
 * )
 * ```
 */
class UTXOSelector(
    private val config: UTXOSelectionConfig = UTXOSelectionConfig.default()
) {

    /**
     * Select UTXOs for a transaction using the configured strategy.
     *
     * @param utxos List of available UTXOs
     * @param targetAmount Amount to send in satoshis
     * @param feeRate Fee rate in satoshis per virtual byte
     * @param strategy Override the configured strategy (optional)
     * @return UTXOSelection with selected UTXOs and calculated values
     * @throws InsufficientFundsException if unable to meet the target amount
     */
    fun select(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long,
        strategy: UTXOSelectionStrategy = config.strategy
    ): UTXOSelection {
        // Filter UTXOs based on config
        val eligibleUTXOs = utxos.filter { utxo ->
            val isConfirmed = utxo.confirmed || config.includeUnconfirmed
            val isNotDust = !utxo.isDust(config.dustThreshold)
            isConfirmed && isNotDust
        }

        if (eligibleUTXOs.isEmpty()) {
            throw InsufficientFundsException("No eligible UTXOs available")
        }

        val totalAvailable = eligibleUTXOs.sumOf { it.value }
        if (totalAvailable < targetAmount) {
            throw InsufficientFundsException(
                "Insufficient funds. Available: $totalAvailable satoshis, Required: $targetAmount satoshis"
            )
        }

        // Determine actual strategy if OPTIMAL is selected
        val actualStrategy = when (strategy) {
            UTXOSelectionStrategy.OPTIMAL -> UTXOSelectionStrategy.suggest(
                utxoCount = eligibleUTXOs.size,
                targetAmount = targetAmount,
                totalAvailable = totalAvailable,
                feeRate = feeRate
            )
            else -> strategy
        }

        return when (actualStrategy) {
            UTXOSelectionStrategy.LARGEST_FIRST -> selectLargestFirst(eligibleUTXOs, targetAmount, feeRate)
            UTXOSelectionStrategy.SMALLEST_FIRST -> selectSmallestFirst(eligibleUTXOs, targetAmount, feeRate)
            UTXOSelectionStrategy.BRANCH_AND_BOUND -> selectBranchAndBound(eligibleUTXOs, targetAmount, feeRate)
            UTXOSelectionStrategy.FIFO -> selectFIFO(eligibleUTXOs, targetAmount, feeRate)
            UTXOSelectionStrategy.RANDOM -> selectRandom(eligibleUTXOs, targetAmount, feeRate)
            UTXOSelectionStrategy.OPTIMAL -> selectBranchAndBound(eligibleUTXOs, targetAmount, feeRate)
        }
    }

    /**
     * Select UTXOs using multiple strategies and return the best result.
     *
     * @param utxos List of available UTXOs
     * @param targetAmount Amount to send in satoshis
     * @param feeRate Fee rate in satoshis per virtual byte
     * @return The selection with the lowest estimated fee
     */
    fun selectOptimal(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        val eligibleUTXOs = utxos.filter { utxo ->
            val isConfirmed = utxo.confirmed || config.includeUnconfirmed
            val isNotDust = !utxo.isDust(config.dustThreshold)
            isConfirmed && isNotDust
        }

        if (eligibleUTXOs.isEmpty()) {
            throw InsufficientFundsException("No eligible UTXOs available")
        }

        val strategies = listOf(
            { selectLargestFirst(eligibleUTXOs, targetAmount, feeRate) },
            { selectBranchAndBound(eligibleUTXOs, targetAmount, feeRate) },
            { selectSmallestFirst(eligibleUTXOs, targetAmount, feeRate) }
        )

        var bestSelection: UTXOSelection? = null
        var lowestFee = Long.MAX_VALUE

        for (strategyFn in strategies) {
            try {
                val selection = strategyFn()
                if (selection.estimatedFee < lowestFee) {
                    bestSelection = selection
                    lowestFee = selection.estimatedFee
                }
            } catch (e: InsufficientFundsException) {
                // Try next strategy
            }
        }

        return bestSelection ?: throw InsufficientFundsException(
            "Unable to select UTXOs. Required: $targetAmount satoshis"
        )
    }

    /**
     * Largest First strategy - selects the largest UTXOs first.
     */
    private fun selectLargestFirst(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        val sorted = utxos.sortedByDescending { it.value }
        return selectSequentially(sorted, targetAmount, feeRate)
    }

    /**
     * Smallest First strategy - selects the smallest UTXOs first.
     */
    private fun selectSmallestFirst(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        val sorted = utxos.sortedBy { it.value }
        return selectSequentially(sorted, targetAmount, feeRate)
    }

    /**
     * FIFO strategy - selects UTXOs in order (assumes they're ordered by time).
     */
    private fun selectFIFO(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        // UTXOs are assumed to be in FIFO order already
        return selectSequentially(utxos, targetAmount, feeRate)
    }

    /**
     * Random strategy - randomly selects UTXOs.
     */
    private fun selectRandom(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        val shuffled = utxos.shuffled(Random)
        return selectSequentially(shuffled, targetAmount, feeRate)
    }

    /**
     * Sequential selection helper - adds UTXOs until target is met.
     */
    private fun selectSequentially(
        sortedUTXOs: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        var total = 0L
        val selected = mutableListOf<UTXO>()

        for (utxo in sortedUTXOs) {
            if (selected.size >= config.maxInputs) break

            selected.add(utxo)
            total += utxo.value

            val estimatedFee = estimateFee(
                inputCount = selected.size,
                outputCount = 2, // Target address + change
                feeRate = feeRate
            )

            if (total >= targetAmount + estimatedFee) {
                val change = total - targetAmount - estimatedFee

                // If change is below dust threshold, add it to the fee
                val (finalChange, finalFee) = if (change < config.dustThreshold) {
                    0L to (estimatedFee + change)
                } else {
                    change to estimatedFee
                }

                return UTXOSelection(
                    selectedUTXOs = selected,
                    totalValue = total,
                    change = finalChange,
                    estimatedFee = finalFee
                )
            }
        }

        throw InsufficientFundsException(
            "Insufficient funds. Available: $total, Required: ${targetAmount + estimateFee(selected.size, 2, feeRate)}"
        )
    }

    /**
     * Branch and Bound algorithm - finds optimal selection to avoid change.
     *
     * This implementation is inspired by Bitcoin Core's BnB. It tries to find a combination
     * of UTXOs that matches the target amount + fees exactly, so no change output is needed.
     */
    private fun selectBranchAndBound(
        utxos: List<UTXO>,
        targetAmount: Long,
        feeRate: Long
    ): UTXOSelection {
        // Sort UTXOs by value descending for better pruning
        val sortedUtxos = utxos.sortedByDescending { it.value }
        
        var bestSelection: List<UTXO>? = null
        var minWaste = Long.MAX_VALUE
        val maxTries = config.maxBranchAndBoundTries
        var currentTries = 0

        // Cost of adding a change output (we want to avoid this)
        val costOfChange = estimateFee(0, 1, feeRate)

        fun search(
            index: Int,
            currentValue: Long,
            selected: MutableList<UTXO>
        ) {
            currentTries++
            if (currentTries > maxTries) return

            // Calculate current fee based on selected inputs (no change output)
            val currentFee = estimateFee(selected.size, 1, feeRate)
            val targetWithFee = targetAmount + currentFee
            val targetRangeMax = targetWithFee + costOfChange

            // If we are over the range, backtrack
            if (currentValue > targetRangeMax) return

            // If we found a valid selection in range [targetWithFee, targetRangeMax]
            if (currentValue >= targetWithFee && currentValue <= targetRangeMax) {
                val waste = currentValue - targetWithFee
                if (waste < minWaste) {
                    minWaste = waste
                    bestSelection = ArrayList(selected)
                }
                // Continue searching for potentially better matches
            }

            // End of UTXO list
            if (index >= sortedUtxos.size) return

            // Recursive branch: Inclusion
            selected.add(sortedUtxos[index])
            search(index + 1, currentValue + sortedUtxos[index].value, selected)
            selected.removeAt(selected.size - 1)

            // Recursive branch: Exclusion
            search(index + 1, currentValue, selected)
        }

        search(0, 0, mutableListOf())

        return bestSelection?.let { selection ->
            val total = selection.sumOf { it.value }
            val fee = estimateFee(selection.size, 1, feeRate) // No change output
            UTXOSelection(
                selectedUTXOs = selection,
                totalValue = total,
                change = 0,
                estimatedFee = total - targetAmount
            )
        } ?: selectLargestFirst(utxos, targetAmount, feeRate) // Fallback to Largest First (will have change)
    }

    /**
     * Estimate transaction fee based on inputs and outputs.
     *
     * @param inputCount Number of transaction inputs
     * @param outputCount Number of transaction outputs
     * @param feeRate Fee rate in satoshis per virtual byte
     * @param scriptType Type of script (affects input size)
     * @return Estimated fee in satoshis
     */
    fun estimateFee(
        inputCount: Int,
        outputCount: Int,
        feeRate: Long,
        scriptType: ScriptType = ScriptType.P2WPKH
    ): Long {
        val inputSize = when (scriptType) {
            ScriptType.P2PKH -> INPUT_SIZE_P2PKH
            ScriptType.P2SH -> INPUT_SIZE_P2SH
            ScriptType.P2WPKH -> INPUT_SIZE_P2WPKH
            ScriptType.P2WSH -> INPUT_SIZE_P2WSH
            ScriptType.P2TR -> INPUT_SIZE_P2TR
            ScriptType.UNKNOWN -> INPUT_SIZE_P2PKH
        }

        val outputSize = OUTPUT_SIZE_P2WPKH // Default to SegWit outputs

        val size = BASE_TX_SIZE + (inputCount * inputSize) + (outputCount * outputSize)
        return size.toLong() * feeRate
    }

    /**
     * Validate a UTXO selection.
     *
     * @param selection The selection to validate
     * @param targetAmount The target amount that was requested
     * @param feeRate The fee rate used
     * @return true if the selection is valid
     */
    fun validateSelection(
        selection: UTXOSelection,
        targetAmount: Long,
        feeRate: Long
    ): Boolean {
        val totalInput = selection.selectedUTXOs.sumOf { it.value }
        val outputCount = if (selection.change > 0) 2 else 1
        val estimatedFee = estimateFee(selection.selectedUTXOs.size, outputCount, feeRate)

        return totalInput >= targetAmount + estimatedFee
    }

    companion object {
        // Transaction size constants (in virtual bytes)
        const val BASE_TX_SIZE = 10
        const val INPUT_SIZE_P2PKH = 148
        const val INPUT_SIZE_P2SH = 91
        const val INPUT_SIZE_P2WPKH = 68
        const val INPUT_SIZE_P2WSH = 104
        const val INPUT_SIZE_P2TR = 57
        const val OUTPUT_SIZE_P2PKH = 34
        const val OUTPUT_SIZE_P2WPKH = 31
        const val OUTPUT_SIZE_P2TR = 43
    }
}

/**
 * Exception thrown when there are insufficient funds to complete a transaction.
 */
class InsufficientFundsException(message: String) : Exception(message)
