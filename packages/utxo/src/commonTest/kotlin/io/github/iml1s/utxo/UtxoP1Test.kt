package io.github.iml1s.utxo

import kotlin.test.Test
import kotlin.test.assertTrue

class UtxoP1Test {

    @Test
    fun branchAndBoundRespectsMaxInputs() {
        val utxos = (1..8).map { i ->
            UTXO(txid = "tx$i", vout = 0, value = 10_000L, confirmed = true)
        }
        // feeRate 0 makes BnB's no-change window an exact 5-coin match (50_000).
        val unconstrained = UTXOSelector(
            UTXOSelectionConfig(strategy = UTXOSelectionStrategy.BRANCH_AND_BOUND, maxInputs = 100)
        ).select(utxos, targetAmount = 50_000L, feeRate = 0)
        assertTrue(
            unconstrained.selectedUTXOs.size > 2,
            "fixture must need more than 2 inputs when uncapped (got ${unconstrained.selectedUTXOs.size})"
        )

        val capped = UTXOSelector(
            UTXOSelectionConfig(strategy = UTXOSelectionStrategy.BRANCH_AND_BOUND, maxInputs = 2)
        )
        val result = runCatching { capped.select(utxos, targetAmount = 50_000L, feeRate = 0) }
        assertTrue(
            result.isFailure || result.getOrThrow().selectedUTXOs.size <= 2,
            "BnB must not exceed maxInputs=2 (got ${result.getOrNull()?.selectedUTXOs?.size})"
        )
    }

    @Test
    fun validatorRejectsNonConservationAndDuplicates() {
        val selector = UTXOSelector()
        val utxo = UTXO(txid = "aa", vout = 0, value = 10_000L, confirmed = true)
        val dup = UTXOSelection(
            selectedUTXOs = listOf(utxo, utxo),
            totalValue = 20_000L,
            change = 0,
            estimatedFee = 10_000L
        )
        assertTrue(!selector.validateSelection(dup, 10_000L, 1))

        val unbalanced = UTXOSelection(
            selectedUTXOs = listOf(utxo),
            totalValue = 10_000L,
            change = 1,
            estimatedFee = 1
        )
        assertTrue(!selector.validateSelection(unbalanced, 1_000L, 1))
    }
}
