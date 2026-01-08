/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21

import org.kotlinbitcointools.bip21.parameters.Amount
import org.kotlinbitcointools.bip21.parameters.Label
import org.kotlinbitcointools.bip21.parameters.Lightning
import org.kotlinbitcointools.bip21.parameters.Message
import org.kotlinbitcointools.bip21.parameters.OtherParameter
import org.kotlinbitcointools.bip21.parameters.fromBitcoinIntoAmount
import java.net.URISyntaxException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class Bip21URITest {
    @Test
    fun `URI cannot be built if scheme is not present`() {
        val uri = "1andreas3batLhQa2FawWjeyjCqyBzypd"
        assertFailsWith<IllegalArgumentException> {
            Bip21URI.fromUri(uri)
        }
    }

    @Test
    fun `URI only has bitcoin address`() {
        val uri =
            Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd")

        assertEquals(
            expected = "1andreas3batLhQa2FawWjeyjCqyBzypd",
            actual = uri.address,
        )
        assertEquals(null, uri.amount)
        assertEquals(null, uri.label)
        assertEquals(null, uri.message)
        assertEquals(null, uri.otherParameters)
    }

    @Test
    fun `Schema is case insensitive`() {
        Bip21URI.fromUri("BiTcOiN:1andreas3batLhQa2FawWjeyjCqyBzypd")
        Bip21URI.fromUri("BITCOIN:1andreas3batLhQa2FawWjeyjCqyBzypd")
        Bip21URI.fromUri("Bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd")
    }

    @Test
    fun `URI has bech32 address in all caps`() {
        val uri = Bip21URI.fromUri("bitcoin:BC1Q0XCQPZRKY6EFF2G52QDYE53XKK9JXKVRH6YHYW")

        assertEquals(
            expected = "BC1Q0XCQPZRKY6EFF2G52QDYE53XKK9JXKVRH6YHYW",
            actual = uri.address,
        )
    }

    @Test
    fun `URI with full standard parameters`() {
        val uri = Bip21URI.fromUri(
            "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
        )

        assertEquals("1andreas3batLhQa2FawWjeyjCqyBzypd", uri.address)
        assertNotNull(uri.amount)
        assertEquals(Amount(5000000000), uri.amount)
        assertEquals(Label("Luke-Jr"), uri.label)
        assertEquals(Message("Donation for project xyz"), uri.message)
        assertEquals(null, uri.otherParameters)
    }

    @Test
    fun `URI with question mark character`() {
        val uri =
            Bip21URI.fromUri(
                "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Luke-Jr&message=Donation?%20for%20project%20xyz",
            )

        assertEquals("1andreas3batLhQa2FawWjeyjCqyBzypd", uri.address)
        assertNotNull(uri.amount)
        assertEquals(Amount(5000000000), uri.amount)
        assertEquals(Label("Luke-Jr"), uri.label)
        assertEquals(Message("Donation? for project xyz"), uri.message)
        assertEquals(null, uri.otherParameters)
    }

    @Test
    fun `URI has parameters we don't know`() {
        val uri = Bip21URI.fromUri(
            "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=100&arg1=50&arg2=999&arg3=abc%20abc"
        )

        assertEquals("1andreas3batLhQa2FawWjeyjCqyBzypd", uri.address)
        assertNotNull(uri.amount)
        assertEquals(Amount(10_000_000_000L), uri.amount)
        assertEquals(null, uri.label)
        assertEquals(null, uri.message)
        assertTrue(uri.otherParameters?.contains(OtherParameter(key = "arg1", value = "50")) == true)
        assertTrue(uri.otherParameters?.contains(OtherParameter(key = "arg2", value = "999")) == true)
        assertTrue(uri.otherParameters?.contains(OtherParameter(key = "arg3", value = "abc abc")) == true)
    }

    @Test
    fun `URI has extreme bitcoin amounts`() {
        Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=21000000")
        Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=21000000.0000000000000",)
        Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=0.00000001")
        Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=000000000000.00000001",)
    }

    @Test
    fun `Build URI using spaces in values of label message and other parameters`() {
        val uri =
            Bip21URI(
                address = "1andreas3batLhQa2FawWjeyjCqyBzypd",
                amount = Amount(5000000000),
                label = Label("Kotlin Bitcoin Tools"),
                message = Message("Building tools for bitcoin in Kotlin"),
                otherParameters =
                    listOf(
                        OtherParameter("otherparameter1", "abc abc"),
                        OtherParameter("otherparameter2", "def def"),
                    ),
            )
        assertEquals(
            expected = "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Kotlin%20Bitcoin%20Tools&message=Building%20tools%20for%20bitcoin%20in%20Kotlin&otherparameter1=abc%20abc&otherparameter2=def%20def",
            actual = uri.toURI(),
        )
    }

    @Test
    fun `Build URI using spaces in names of parameters`() {
        val uri =
            Bip21URI(
                address = "1andreas3batLhQa2FawWjeyjCqyBzypd",
                otherParameters =
                    listOf(
                        OtherParameter("other parameter 1", "abc abc"),
                        OtherParameter("other parameter 2", "def def"),
                    ),
            )
        assertEquals(
            expected = "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?other%20parameter%201=abc%20abc&other%20parameter%202=def%20def",
            actual = uri.toURI(),
        )
    }

    // Unified QRs are defined here: https://bitcoinqr.dev/
    @Test
    fun `Can parse unified QRs`() {
        val unifiedQr = "bitcoin:BC1QYLH3U67J673H6Y6ALV70M0PL2YZ53TZHVXGG7U?amount=0.00001&label=sbddesign%3A%20For%20lunch%20Tuesday&message=For%20lunch%20Tuesday&lightning=LNBC10U1P3PJ257PP5YZTKWJCZ5FTL5LAXKAV23ZMZEKAW37ZK6KMV80PK4XAEV5QHTZ7QDPDWD3XGER9WD5KWM36YPRX7U3QD36KUCMGYP282ETNV3SHJCQZPGXQYZ5VQSP5USYC4LK9CHSFP53KVCNVQ456GANH60D89REYKDNGSMTJ6YW3NHVQ9QYYSSQJCEWM5CJWZ4A6RFJX77C490YCED6PEMK0UPKXHY89CMM7SCT66K8GNEANWYKZGDRWRFJE69H9U5U0W57RRCSYSAS7GADWMZXC8C6T0SPJAZUP6"
        val uri = Bip21URI.fromUri(unifiedQr)

        assertEquals(
            expected =
                Lightning(
                    "LNBC10U1P3PJ257PP5YZTKWJCZ5FTL5LAXKAV23ZMZEKAW37ZK6KMV80PK4XAEV5QHTZ7QDPDWD3XGER9WD5KWM36YPRX7U3QD36KUCMGYP282ETNV3SHJCQZPGXQYZ5VQSP5USYC4LK9CHSFP53KVCNVQ456GANH60D89REYKDNGSMTJ6YW3NHVQ9QYYSSQJCEWM5CJWZ4A6RFJX77C490YCED6PEMK0UPKXHY89CMM7SCT66K8GNEANWYKZGDRWRFJE69H9U5U0W57RRCSYSAS7GADWMZXC8C6T0SPJAZUP6",
                ),
            actual = uri.lightning,
        )
    }

    @Test
    fun `Correctly creates unified QRs`() {
        val uri =
            Bip21URI(
                address = "BC1QYLH3U67J673H6Y6ALV70M0PL2YZ53TZHVXGG7U",
                amount = "0.00001".fromBitcoinIntoAmount(),
                label = Label("sbddesign: For lunch Tuesday"),
                message = Message("For lunch Tuesday"),
                lightning =
                    Lightning(
                        "LNO1PG257ENXV4EZQCNEYPE82UM50YNHXGRWDAJX283QFWDPL28QQMC78YMLVHMXCSYWDK5WRJNJ36JRYG488QWLRNZYJCZS",
                    ),
            )

        assertEquals(
            actual = uri.toURI(),
            expected = "bitcoin:BC1QYLH3U67J673H6Y6ALV70M0PL2YZ53TZHVXGG7U?amount=0.00001&label=sbddesign%3A%20For%20lunch%20Tuesday&message=For%20lunch%20Tuesday&lightning=LNO1PG257ENXV4EZQCNEYPE82UM50YNHXGRWDAJX283QFWDPL28QQMC78YMLVHMXCSYWDK5WRJNJ36JRYG488QWLRNZYJCZS",
        )
    }

    @Test
    fun `URI has duplicate parameters`() {
        val exception =
            assertFailsWith<InvalidURIException> {
                Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=100&amount=50",)
            }
        assertEquals("Invalid URI: duplicate parameter", exception.message)
    }

    @Test
    fun `URI doesn't use bitcoin scheme`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri("https://example.com")
            }
        assertEquals("Invalid scheme 'https://', expected 'bitcoin:'", exception.message)
    }

    @Test
    fun `URI has no address`() {
        val exception = assertFailsWith<URISyntaxException> { Bip21URI.fromUri("bitcoin:") }
        assertEquals("Expected scheme-specific part at index 8: bitcoin:", exception.message)
    }

    @Test
    fun `URI has question mark character but empty query`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?")
            }
        assertEquals("'?' character indicates query part but the part is empty", exception.message)
    }

    @Test
    fun `URI has a parameter missing an '=' sign`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri(
                    "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount100&arg1=50&arg2=999&arg3=abc%20abc",
                )
            }
        assertEquals("Invalid URI: parameter amount100 does not have a separator", exception.message)
    }

    @Test
    fun `URI has invalid bitcoin amounts`() {
        val exception1 =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=21000001")
            }
        val exception2 =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=21000000.00000001",)
            }
        val exception3 =
            assertFailsWith<IllegalArgumentException> {
                Bip21URI.fromUri("bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=0.000000001",)
            }

        assertEquals("Invalid amount: 21000001 (above possible number of bitcoin)", exception1.message)
        assertEquals("Invalid amount: 21000000.00000001 (above possible number of bitcoin)", exception2.message)
        assertEquals("Invalid amount: 0.000000001 (amount is below 1 satoshi)", exception3.message)
    }
}
