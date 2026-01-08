package io.github.iml1s.wallet

import io.github.iml1s.client.bitcoin.MempoolSpaceClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

fun main() {
    runBlocking {
        println("=== Bitcoin Wallet Demo ===")
        
        // 1. Setup Blockchain Client
        val json = Json { ignoreUnknownKeys = true }
        val httpClient = HttpClient(CIO) {
            install(ContentNegotiation) {
                json(json)
            }
        }
        val client = MempoolSpaceClient(httpClient)
        
        // 2. Initialize Wallet
        // Note: Demo uses a fixed address since we don't have crypto-pure for key derivation yet
        println("Initializing wallet...")
        val wallet = Wallet(client, Wallet.Network.MAINNET)
        
        // 3. Demo Operations
        val demoAddress = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" // Bitcoin Genesis extraction address (active)
        println("Fetching data for demo address: $demoAddress")
        
        try {
            val balance = wallet.getBalance(demoAddress)
            println("Balance: $balance sats")
            
            val utxos = wallet.getUTXOs(demoAddress)
            println("Found ${utxos.size} UTXOs")
            
            val fees = wallet.getFeeRates()
            println("Recommended Fee (Fast): ${fees.fast} sat/vB")
            
            if (utxos.isNotEmpty()) {
                println("Selecting coins for 10,000 sats payment...")
                val selection = wallet.selectCoins(
                    utxos = utxos,
                    targetAmount = 10_000,
                    feeRate = fees.fast
                )
                
                if (selection.isSuccess) {
                    println("Coin Selection Success!")
                    println("Selected ${selection.selectedUtxos.size} inputs")
                    println("Total Input: ${selection.totalSelected}")
                    println("Miner Fee: ${selection.fee}")
                    println("Change: ${selection.change}")
                } else {
                    println("Coin Selection Failed: Insufficient funds or dust.")
                }
            }
            
        } catch (e: Exception) {
            println("Error during demo: ${e.message}")
            e.printStackTrace()
        } finally {
            httpClient.close()
        }
    }
}
