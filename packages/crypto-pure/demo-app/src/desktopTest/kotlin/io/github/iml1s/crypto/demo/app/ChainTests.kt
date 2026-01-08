package io.github.iml1s.crypto.demo.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Ignore
import org.junit.Rule
import org.junit.Test

class ChainTests {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun testChainSendDialogs() {
        println("ChainTests: Starting testChainSendDialogs")
        rule.setContent {
            App(isMock = true)
        }

        // 1. Generate Wallet
        rule.onNodeWithText("Load Wallet & Check Balances").performClick()
        
        // Wait for list to load
        // 1. Ethereum check
        rule.waitUntil(timeoutMillis = 15000) {
            rule.onAllNodesWithText("Ethereum", useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }

        // 2. Test Bitcoin Send
        rule.onNodeWithText("Send Bitcoin", useUnmergedTree = true).performScrollTo().performClick()
        rule.waitUntil(timeoutMillis = 5000) {
            rule.onAllNodesWithText("Cancel", useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Cancel", useUnmergedTree = true).performClick()

        // 3. Test Ethereum Send
        rule.onNodeWithText("Send Ethereum", useUnmergedTree = true).performScrollTo().performClick()
        rule.waitUntil(timeoutMillis = 5000) {
            rule.onAllNodesWithText("Cancel", useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Cancel", useUnmergedTree = true).performClick()

        // 4. Test Solana Send
        rule.onNodeWithText("Send Solana", useUnmergedTree = true).performScrollTo().performClick()
        rule.waitUntil(timeoutMillis = 5000) {
            rule.onAllNodesWithText("Cancel", useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithText("Cancel", useUnmergedTree = true).performClick()
    }

    @Test
    fun testNetworkToggle() {
        rule.setContent {
            App(isMock = true)
        }

        // Default is Mainnet
        rule.onNodeWithText("Mainnet").assertExists()

        // Toggle to Testnet
        rule.onNodeWithTag("networkToggle").performClick()

        // Click Load Wallet to refresh addresses
        rule.onNodeWithText("Load Wallet & Check Balances").performClick()

        // Check for Testnet paths/addresses
        rule.waitUntil(timeoutMillis = 5000) {
             // Mock update sends "m/84'/1'/0'/0/0" for Testnet Bitcoin
             rule.onAllNodesWithText("m/84'/1'/0'/0/0", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
        
        // Toggle back to Mainnet
        rule.onNodeWithTag("networkToggle").performClick()

        // Click Load Wallet to refresh addresses
        rule.onNodeWithText("Load Wallet & Check Balances").performClick()
        
        rule.waitUntil(timeoutMillis = 5000) {
             rule.onAllNodesWithText("m/84'/0'/0'/0/0", substring = true).fetchSemanticsNodes().isNotEmpty()
        }
    }
}
