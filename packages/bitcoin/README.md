# bitcoin-kmp

<<<<<<< HEAD
> [!IMPORTANT]
> **Fork Information**: This project is forked from [ACINQ/bitcoin-kmp](https://github.com/ACINQ/bitcoin-kmp). It has been modified to support **WatchOS** and **Pure Kotlin Cryptography** for specific platforms.

<p align="center">
  <img src="./docs/images/hero.png" alt="Bitcoin KMP Hero" width="100%">
</p>

<p align="center">
  <a href="https://jitpack.io/#ImL1s/kotlin-bitcoin-kmp"><img src="https://jitpack.io/v/ImL1s/kotlin-bitcoin-kmp.svg" alt="JitPack"></a>
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Android%20%7C%20iOS%20%7C%20watchOS%20%7C%20JVM-orange" alt="Platform"></a>
  <a href="#"><img src="https://img.shields.io/badge/WatchOS-Supported-green?style=for-the-badge&logo=apple" alt="WatchOS Supported"></a>
</p>

<p align="center">
  <strong>₿ Powerful Bitcoin Cryptography library for Kotlin Multiplatform.</strong>
</p>

---

## 🏗️ Architecture

```mermaid
graph TD
    subgraph "Apple Target Optimization"
        A[Apple Main] --> B{Platform Check}
        B -->|watchOS| C[CoreCrypto Digest]
        B -->|watchOS| D[Pure Kotlin Pbkdf2]
        B -->|iOS| E[CommonCrypto / Native]
    end

    subgraph "Core Components"
        F[BIP32 / BIP39] --> G[Key Derivation]
        C --> H[Hash Functions]
        D --> I[Key Stretching]
    end
```

---

## ✨ Features
- **WatchOS Native**: Custom `Digest` and `Pbkdf2` implementations optimized for S-series chips.
- **Full BIP Support**: BIP32, BIP39, BIP44, BIP141 (SegWit).
- **CoreCrypto Integration**: High-performance hashing on Apple platforms via native bindings.
- **Pure Kotlin Fallbacks**: Reliability on platforms with limited native library support.
=======
<p align="center">
  <img src="../docs/images/kmp_crypto_banner.png" alt="bitcoin-kmp" width="100%">
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin"></a>
  <a href="#"><img src="https://img.shields.io/badge/multiplatform-android%20%7C%20ios%20%7C%20jvm%20%7C%20linux-brightgreen" alt="Multiplatform"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

<p align="center">
  <strong>🪙 A simple, comprehensive Kotlin Multiplatform implementation of the Bitcoin protocol.</strong>
</p>

---

## 🏗️ Protocol Architecture

```mermaid
graph TB
    subgraph "Protocol Layer"
        P[Parser] --> B[Block / Header]
        P --> T[Transaction]
        P --> S[Script]
    end
    
    subgraph "Logic & Verification"
        T --> VAL[Validation Engine]
        S --> EXEC[Script Execution / Interpreter]
        EXEC --> SG[SegWit / Taproot]
    end
    
    subgraph "Keys & Wallets"
        HD[BIP32 / BIP39] --> SIGN[Signer / PSBT]
        SIGN --> T
    end
```

---

## ✨ Features

- **Core Primitives**:
  - Base58 / Bech32 / Bech32m encoding & decoding
  - Block, Header, and Transaction parsing/serialization
  - Script parsing and execution (including SegWit, Taproot, OP_CLTV, OP_CSV)
  
- **Transactions**:
  - Construction & Signing (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, **P2TR**)
  - Partial Signing (BIP174 PSBT v0)
  - Full validation logic

- **Wallets & Keys**:
  - BIP 32 (HD Wallets)
  - BIP 39 (Mnemonic Codes)
  - BIP 86 (Taproot Key Derivation)
>>>>>>> d73479b (fix(ci): add google repo and suppress lint)

---

## 📦 Installation

<<<<<<< HEAD
```kotlin
// build.gradle.kts
implementation("com.github.ImL1s:kotlin-bitcoin-kmp:0.14.0-watchos")
```

---

## 📄 License
MIT License
=======
`bitcoin-kmp` is available on Maven Central.

```kotlin
// build.gradle.kts
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("fr.acinq.bitcoin:bitcoin-kmp:0.19.0")
        }
    }
}
```

> **Note**: For JVM targets, you must also include a `secp256k1` implementation:
> `implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.14.0")`

---

## 🚀 Usage

### Creating and Signing a Transaction

```kotlin
val privateKey = PrivateKey.fromBase58("cRp4uUnreGMZN8vB7nQFX6XWMHU5Lc73HMAhmcDEwHfbgRS66Cqp", Base58.Prefix.SecretKeyTestnet).first
val publicKey = privateKey.publicKey()
val amount = 1000L.toSatoshi()

// 1. Define inputs and outputs
val tx = Transaction(
    version = 1L,
    txIn = listOf(
        TxIn(OutPoint(previousTx.hash, 0), signatureScript = listOf(), sequence = 0xFFFFFFFFL)
    ),
    txOut = listOf(
        TxOut(
            amount = amount, 
            publicKeyScript = listOf(OP_DUP, OP_HASH160, OP_PUSHDATA(pubkeyHash), OP_EQUALVERIFY, OP_CHECKSIG)
        )
    ),
    lockTime = 0L
)

// 2. Sign inputs
val sig = Transaction.signInput(
    tx, 
    0, 
    previousTx.txOut[0].publicKeyScript, 
    SIGHASH_ALL, 
    privateKey
)

// 3. Update the transaction with the signature
val signedTx = tx.updateSigScript(
    0, 
    listOf(OP_PUSHDATA(sig), OP_PUSHDATA(publicKey))
)

// The transaction is now ready to be broadcast!
```

---

## 🎯 Supported Platforms

| Platform | Support | Notes |
|----------|---------|-------|
| **JVM** | ✅ | Primary development & server target |
| **Android** | ✅ | Full support |
| **iOS** | ✅ | Native support via Kotlin Native |
| **Linux** | ⚠️ | Protoyping/Testing only |

---

## 📄 License

Apache License 2.0
>>>>>>> d73479b (fix(ci): add google repo and suppress lint)
