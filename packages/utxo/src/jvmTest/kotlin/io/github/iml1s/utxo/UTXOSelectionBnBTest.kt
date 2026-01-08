package io.github.iml1s.utxo

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UTXOSelectionBnBTest {

    @Test
    fun testBnBExactMatch() {
        val selector = UTXOSelector()
        val utxos = listOf(
            UTXO("tx1", 0, 10_000, true),
            UTXO("tx2", 0, 20_000, true),
            UTXO("tx3", 0, 30_000, true),
            UTXO("tx4", 0, 50_000, true)
        )

        // Fee for 1 input, 1 output (no change), feeRate=1
        // P2WPKH input: 68 vB, output: 31 vB, base: 10 vB = 109 sats
        val estimatedFee = selector.estimateFee(1, 1, 1)
        
        // Target = 30,000 - fee (so total selected = 30,000 exactly covers target + fee)
        // This ensures BnB can find exact match with tx3 (30,000)
        val targetAmount = 30_000L - estimatedFee
        
        val selection = selector.select(
            utxos = utxos,
            targetAmount = targetAmount,
            feeRate = 1,
            strategy = UTXOSelectionStrategy.BRANCH_AND_BOUND
        )
        
        // BnB should find 30,000 UTXO as exact match
        assertEquals(0L, selection.change, "Should have 0 change for exact match")
        assertEquals(1, selection.selectedUTXOs.size)
        assertEquals(30_000L, selection.selectedUTXOs[0].value)
    }

    @Test
    fun testBnBFallsBackToLargestFirst() {
        val selector = UTXOSelector()
        val utxos = listOf(
            UTXO("tx1", 0, 10_000, true),
            UTXO("tx2", 0, 20_000, true),
            UTXO("tx3", 0, 30_000, true)
        )
        
        // Target is impossible to match exactly with available UTXOs
        // BnB should fall back to Largest First (which will have change)
        val targetAmount = 55_000L // Requires all UTXOs (10k + 20k + 30k = 60k)
        
        val selection = selector.select(
            utxos = utxos,
            targetAmount = targetAmount,
            feeRate = 1,
            strategy = UTXOSelectionStrategy.BRANCH_AND_BOUND
        )
        
        // Should fall back and select UTXOs with change
        assertTrue(selection.selectedUTXOs.isNotEmpty())
        assertTrue(selection.totalValue >= targetAmount)
    }
}
