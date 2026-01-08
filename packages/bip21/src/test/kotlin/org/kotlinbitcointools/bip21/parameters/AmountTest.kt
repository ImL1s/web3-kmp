/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AmountTest {
    @Test
    fun `Amount can be created`() {
        val amount = Amount(1000L)
        assertEquals(1000L, amount.sat)
    }

    @Test
    fun `Amount can be created from bitcoin amount formatted string`() {
        val amount0 = "0.001".fromBitcoinIntoAmount()
        assertEquals(100_000L, amount0.sat)

        val amount1 = "212121.00000001".fromBitcoinIntoAmount()
        assertEquals(21212100000001L, amount1.sat)

        val amount2 = "100".fromBitcoinIntoAmount()
        assertEquals(10_000_000_000L, amount2.sat)
    }

    @Test
    fun `Amount cannot be negative`() {
        assertFailsWith<IllegalArgumentException> {
            Amount(-1000L)
        }
    }

    @Test
    fun `Bitcoin amount cannot be negative`() {
        assertFailsWith<IllegalArgumentException> {
            "-0.001".fromBitcoinIntoAmount()
        }
    }

    @Test
    fun `Amount cannot be above MAX_SATOSHI value`() {
        assertFailsWith<IllegalArgumentException> {
            Amount(Long.MAX_VALUE)
        }
    }

    @Test
    fun `Error thrown when building with invalid bitcoin amount`() {
        val tooManyDecimalsAmount = "0.000000001"
        val tooManyBitcoinAmount = "21000001"

        assertFailsWith<IllegalArgumentException> {
            tooManyDecimalsAmount.fromBitcoinIntoAmount()
        }
        assertFailsWith<IllegalArgumentException> {
            tooManyBitcoinAmount.fromBitcoinIntoAmount()
        }
    }

    @Test
    fun `Amount can be converted to bitcoin amount`() {
        val amount = Amount(100_000_000L)
        assertEquals("1", amount.toBitcoin())

        val amount2 = Amount(10_000_000_000L)
        assertEquals("100", amount2.toBitcoin())

        val amount3 = Amount(1L)
        assertEquals("0.00000001", amount3.toBitcoin())

        val amount4 = Amount(10_000_000L)
        assertEquals("0.1", amount4.toBitcoin())

        val amount5 = Amount(0L)
        assertEquals("0", amount5.toBitcoin())
    }
}
