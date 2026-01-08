# kotlin-tx-builder

> [!NOTE]
> **Acknowledgments**: Parts of the transaction building logic (Bitcoin/SegWit) are inspired by and based on [ACINQ/bitcoin-kmp](https://github.com/ACINQ/bitcoin-kmp).

<p align="center">
  <img src="../docs/images/kmp_crypto_banner.png" alt="kotlin-tx-builder" width="100%">
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin"></a>
  <a href="#"><img src="https://img.shields.io/badge/multiplatform-android%20%7C%20ios%20%7C%20watchOS%20%7C%20JVM-orange" alt="Multiplatform"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <strong>🔨 Pure Kotlin Multiplatform library for building and signing cryptocurrency transactions.</strong>
</p>

## 🏗️ Transaction Construction Flow

```mermaid
graph LR
    DSL[Fluent DSL] --> B[Transaction Builder]
    B --> IN[Inputs / OutPoints]
    B --> OUT[Outputs / Scripts]
    
    subgraph "Signing Pipeline"
        IN --> SH[Sighash Calculation]
        SH --> SIGN[Signer Module]
        SIGN --> SIG[Witness / SigScript]
    end
    
    SIG --> TX[Signed Transaction]
    TX --> HEX[Raw Hex Serialization]
```

---

## Features

### Bitcoin (BTC)
- **Transaction Models**: Full support for Legacy and SegWit (BIP141) transactions.
- **PSBT (BIP174)**: Partially Signed Bitcoin Transaction support for interoperability.
- **Taproot (BIP341)**: Support for Taproot Key Path signing (`hashForSigningTaprootKeyPath`).
- **Serialization**: Full raw transaction serialization/deserialization.

### Ethereum (ETH)
- **Legacy Transactions**: Original format (requesting gas price).
- **EIP-1559**: Modern fee market transactions (Base Fee + Priority Fee).
- **RLP Encoding**: Recursive Length Prefix encoding for all transaction types.
- **EIP-155**: Replay attack protection.

## 📦 Installation

```kotlin
// build.gradle.kts
commonMain.dependencies {
    implementation("io.github.iml1s:kotlin-tx-builder:1.0.0")
    // Address management (optional but recommended for DSL)
    implementation("io.github.iml1s:kotlin-address:1.0.0") 
}
```

## Usage

### 🛠️ Fluent DSL (Recommended)

The easiest way to build a Bitcoin transaction is using the `tx` DSL. It handles Script generation and address decoding automatically.

```kotlin
import io.github.iml1s.tx.bitcoin.tx

val transaction = tx {
    // 1. Add Input
    input {
        txid = "7b6632fce3914fd9b098a30ddb03511ebfa393c52ee81329c8e2392728452395"
        vout = 0
    }

    // 2. Add Outputs (using address)
    output {
        address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" // Bech32 (SegWit)
        amount = 50_000 // satoshis
    }

    output {
        address = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy" // P2SH
        amount = 25_000
    }
}

// 3. Serialize
val rawTx = transaction.serialize()
```

### Bitcoin PSBT

```kotlin
val tx = Transaction(...)
val psbt = Psbt(
    global = PsbtGlobal().apply { 
        // Add unsigned tx
    },
    inputs = listOf(...),
    outputs = listOf(...)
)
val serialized = psbt.serialize()
```

### Ethereum EIP-1559

```kotlin
val tx = Eip1559Transaction(
    chainId = 1,
    nonce = 0,
    maxPriorityFeePerGas = ...,
    maxFeePerGas = ...,
    gasLimit = 21000,
    to = "0x...",
    value = ...,
    data = byteArrayOf()
)

val rlpEncoded = tx.encode(forSigning = true)
```

### Taproot Signing (BIP-341)

```kotlin
// Calculate Sighash for Taproot Key Spending
val sighash = tx.hashForSigningTaprootKeyPath(
    inputIndex = 0,
    prevOutputs = listOf(utxo1, utxo2), // Must provide all spent outputs
    sighashType = Transaction.SIGHASH_DEFAULT
)

// Sign with schnorr (using kotlin-crypto-pure)
val signature = Secp256k1Pure.schnorrSign(sighash, privateKey)
```
