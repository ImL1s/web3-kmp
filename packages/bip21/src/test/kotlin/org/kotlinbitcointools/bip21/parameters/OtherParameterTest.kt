/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import kotlin.test.Test
import kotlin.test.assertEquals

class OtherParameterTest {
    @Test
    fun `Encode a random parameter`() {
        val parameter = OtherParameter("random", "value")
        assertEquals("&random=value", parameter.encode())
    }
}
