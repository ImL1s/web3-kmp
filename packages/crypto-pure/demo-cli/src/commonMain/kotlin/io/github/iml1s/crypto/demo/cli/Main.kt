package io.github.iml1s.crypto.demo.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.option
import io.github.iml1s.crypto.*
import io.github.andreypfau.curve25519.ed25519.Ed25519

class WalletGenerator : CliktCommand(name = "crypto-cli") {
    
    override fun help(context: com.github.ajalt.clikt.core.Context): String = "🦄 Universal Multi-Chain Wallet Generator"

    private val mnemonic by option("-m", "--mnemonic", help = "BIP39 mnemonic phrase")
        .default("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

    override fun run() {
        echo("=".repeat(60))
        echo("🦄 kotlin-crypto-pure Universal Wallet Demo")
        echo("=".repeat(60))
        echo()
        echo("Mnemonic: ${mnemonic.take(30)}...")
        echo()

        // Generate seed
        val seed = Pbkdf2.bip39Seed(mnemonic, "")
        echo("Seed: ${Hex.encode(seed).take(32)}...")
        echo()

        // === Bitcoin (BIP44) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🟠 Bitcoin (BTC)                                         ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val btcKey = Bip32.derivePath(seed, "m/44'/0'/0'/0/0")
            val btcPub = Secp256k1Pure.generatePublicKey(btcKey.privateKey)
            echo("Path: m/44'/0'/0'/0/0")
            echo("Private Key: ${Hex.encode(btcKey.privateKey)}")
            echo("Public Key:  ${Hex.encode(btcPub)}")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Ethereum (BIP44) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🔷 Ethereum (ETH)                                        ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val ethKey = Bip32.derivePath(seed, "m/44'/60'/0'/0/0")
            val ethAddress = PureEthereumCrypto.getEthereumAddress(Hex.encode(ethKey.privateKey))
            echo("Path: m/44'/60'/0'/0/0")
            echo("Address: $ethAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Solana (Ed25519) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ ☀️  Solana (SOL)                                          ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val solSeed = Bip32.derivePath(seed, "m/44'/501'/0'/0'").privateKey
            val solPrivKey = Ed25519.keyFromSeed(solSeed)
            val solPubKey = solPrivKey.publicKey().toByteArray()
            val solAddress = Solana.getAddress(solPubKey)
            echo("Path: m/44'/501'/0'/0'")
            echo("Address: $solAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === TON (The Open Network) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 💎 TON                                                   ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val tonKeypair = Ton.keyPairFromMnemonic(mnemonic)
            val tonAddress = Ton.getAddress(tonKeypair.publicKey, workchain = 0, bounceable = false)
            echo("Address (Non-Bounceable): $tonAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Polkadot (Sr25519) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🟣 Polkadot (DOT)                                        ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val dotKeypair = Sr25519.keypairFromSeed(seed.copyOfRange(0, 32))
            val dotAddress = Polkadot.getAddress(dotKeypair.publicKey, networkId = 0)
            echo("Address (SS58): $dotAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Cosmos (Bech32) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ ⚛️  Cosmos (ATOM)                                         ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val cosmosKey = Bip32.derivePath(seed, "m/44'/118'/0'/0/0")
            val cosmosPub = Secp256k1Pure.generatePublicKey(cosmosKey.privateKey, compressed = true)
            val cosmosAddress = Cosmos.getAddress(cosmosPub, hrp = "cosmos")
            echo("Path: m/44'/118'/0'/0/0")
            echo("Address: $cosmosAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Avalanche X-Chain ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🔺 Avalanche X-Chain                                     ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val avaxKey = Bip32.derivePath(seed, "m/44'/9000'/0'/0/0")
            val avaxPub = Secp256k1Pure.generatePublicKey(avaxKey.privateKey, compressed = true)
            val avaxAddress = Avalanche.getXChainAddress(avaxPub)
            echo("Path: m/44'/9000'/0'/0/0")
            echo("Address: $avaxAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Near ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🌐 Near Protocol                                         ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val nearKey = Bip32.derivePath(seed, "m/44'/397'/0'")
            val nearPriv = Ed25519.keyFromSeed(nearKey.privateKey)
            val nearAddress = Near.getImplicitAccountId(nearPriv.publicKey().toByteArray())
            echo("Path: m/44'/397'/0'")
            echo("Address: $nearAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Sui ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🌊 Sui                                                   ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val suiKey = Bip32.derivePath(seed, "m/44'/784'/0'/0'/0'")
            val suiPriv = Ed25519.keyFromSeed(suiKey.privateKey)
            val suiAddress = Sui.getAddress(suiPriv.publicKey().toByteArray())
            echo("Path: m/44'/784'/0'/0'/0'")
            echo("Address: $suiAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Aptos ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 🍃 Aptos                                                 ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val aptosKey = Bip32.derivePath(seed, "m/44'/637'/0'/0'/0'")
            val aptosPriv = Ed25519.keyFromSeed(aptosKey.privateKey)
            val aptosAddress = Aptos.getAddress(aptosPriv.publicKey().toByteArray())
            echo("Path: m/44'/637'/0'/0'/0'")
            echo("Address: $aptosAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Ripple (XRP) ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ 💧 Ripple (XRP)                                          ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val xrpKey = Bip32.derivePath(seed, "m/44'/144'/0'/0/0")
            val xrpPub = Secp256k1Pure.generatePublicKey(xrpKey.privateKey, compressed = true)
            val xrpAddress = Xrp.getAddress(xrpPub)
            echo("Path: m/44'/144'/0'/0/0")
            echo("Address: $xrpAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        // === Tron ===
        echo("╔══════════════════════════════════════════════════════════╗")
        echo("║ ⚡ Tron (TRX)                                            ║")
        echo("╚══════════════════════════════════════════════════════════╝")
        try {
            val trxKey = Bip32.derivePath(seed, "m/44'/195'/0'/0/0")
            val trxPub = Secp256k1Pure.generatePublicKey(trxKey.privateKey)
            val trxAddress = Tron.getAddress(trxPub)
            echo("Path: m/44'/195'/0'/0/0")
            echo("Address: $trxAddress")
        } catch (e: Exception) {
            echo("Error: ${e.message}")
        }
        echo()

        echo("=".repeat(60))
        echo("✅ Done! Generated addresses for supported blockchains.")
        echo("=".repeat(60))
    }
}

fun main(args: Array<String>) = WalletGenerator().main(args)
