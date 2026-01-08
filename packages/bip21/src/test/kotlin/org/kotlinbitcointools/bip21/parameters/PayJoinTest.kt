/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import org.kotlinbitcointools.bip21.Bip21URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PayJoinTest {
    @Test
    fun `Payjoin parameter is correctly decoded`() {
        val bip21 =
            Bip21URI.fromUri(
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https%3A%2F%2Flocalhost%3A3010",
            )
        println("This is the bip21 URI: ${bip21.toURI()}")
        println("The string representation of the Bip21 object is this: $bip21")

        assertEquals(
            expected = "https://localhost:3010",
            actual = bip21.pj?.value,
        )
    }

    @Test
    fun `PayJoin parameter is correctly encoded`() {
        val bip21 =
            Bip21URI(
                address = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
                amount = Amount(1),
                pj = PayJoin("https://localhost:3010"),
            )

        assertTrue {
            bip21.toURI().contains("pj=https%3A%2F%2Flocalhost%3A3010")
        }
    }

    @Test
    fun `Parameter pjos is set to false if pj parameter is present`() {
        val bip21 =
            Bip21URI(
                address = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
                amount = Amount(1),
                pj = PayJoin("https://localhost:3010"),
            )

        assertFalse {
            bip21.pjos ?: true
        }
    }

    @Test
    fun `Parameter pjos is set to null if there is no pj parameter`() {
        val bip21 =
            Bip21URI(
                address = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX",
                amount = Amount(1),
            )

        assertNull(bip21.pjos)
    }
}
