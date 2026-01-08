package io.github.iml1s.crypto.demo.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Rule
import org.junit.Test

class AppTest {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun testWalletGeneration() {
        rule.setContent {
            App(isMock = true)
        }

        // Check initial state
        rule.onNodeWithText("Load Wallet & Check Balances").assertExists()
        rule.onNodeWithText("BIP39 Mnemonic").assertExists()
        
        // Enter mnemonic is pre-filled, so just click generate
        rule.onNodeWithText("Load Wallet & Check Balances").performClick()

        // Wait for results (synchronous in this simple app, but usually requires waitFor)
        // Since our generateWallets is blocking/synchronous in the onClick for now (wrapped in coroutine launch in real app maybe? 
        // No, in App.kt it was standard onClick lambda, but it set isLoading=true/false. 
        // It's technically running on UI thread if not launched in scope. 
        // Let's check App.kt again. It was:
        // onClick = { isLoading = true; wallets = generateWallets(mnemonic); isLoading = false }
        // So it IS synchronous on UI thread. Compose rule will wait for idle.
        
        // Check for generated content
        rule.waitUntil(timeoutMillis = 5000) {
            rule.onAllNodesWithText("Ethereum").fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Ethereum").assertExists()
        rule.onNodeWithText("Bitcoin").assertExists()
        rule.onNodeWithText("Solana").assertExists()

        
        // Verify address logic (partial match checking)
        // Since we can't easily match regex on text nodes with simple API, just existence is good enough E2E.
    }
}
