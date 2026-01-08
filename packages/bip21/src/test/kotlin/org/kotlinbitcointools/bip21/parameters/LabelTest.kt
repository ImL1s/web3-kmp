/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import kotlin.test.Test
import kotlin.test.assertEquals

class LabelTest {
    @Test
    fun `Encode a label parameter from a string with spaces`() {
        val label = Label("Donation for project xyz")
        assertEquals("&label=Donation%20for%20project%20xyz", label.encode())
    }

    @Test
    fun `Build a label parameter from a sanitized string`() {
        val label = Label.decodeFrom("Donation%20for%20project%20xyz")
        assertEquals("Donation for project xyz", label.value)
    }

    @Test
    fun `Build a label parameter from a string with spaces`() {
        val label = Label.decodeFrom("Donation for project xyz")
        assertEquals("Donation for project xyz", label.value)
    }
}
