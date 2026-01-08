package io.github.iml1s.crypto.demo.cli

import kotlin.test.Test
import kotlin.test.assertTrue
import com.github.ajalt.clikt.core.main

class CliTest {
    @Test
    fun testCliExecution() {
        try {
            // Using main(args) which is the extension function used in real app
            WalletGenerator().main(arrayOf("--mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
        } catch (e: Exception) {
            throw AssertionError("CLI execution failed", e)
        }
    }
}
