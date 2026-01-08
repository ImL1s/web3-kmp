# secp256k1-kmp

> [!IMPORTANT]
> **Fork Information**: This project is forked from [ACINQ/secp256k1-kmp](https://github.com/ACINQ/secp256k1-kmp). It features a **Pure Kotlin** implementation for Apple platforms (iOS/WatchOS) to ensure full compatibility without native C-library dependencies.

<p align="center">
  <img src="./docs/images/hero.png" alt="Secp256k1 KMP Hero" width="100%">
</p>

<p align="center">
  <a href="https://jitpack.io/#ImL1s/kotlin-secp256k1-kmp"><img src="https://jitpack.io/v/ImL1s/kotlin-secp256k1-kmp.svg" alt="JitPack"></a>
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin"></a>
  <a href="#"><img src="https://img.shields.io/badge/Platform-Android%20%7C%20iOS%20%7C%20watchOS%20%7C%20JVM-orange" alt="Platform"></a>
  <a href="#"><img src="https://img.shields.io/badge/WatchOS-Supported-green?style=for-the-badge&logo=apple" alt="WatchOS Supported"></a>
</p>

<p align="center">
  <strong>⚡ High-Performance Secp256k1 Cryptography for all platforms.</strong>
</p>

---

## 🏗️ Architecture

```mermaid
graph TD
    subgraph "Hybrid Implementation"
        A[App Code] --> B{Secp256k1 Provider}
        B -->|Android / JVM| C[Native libsecp256k1 via JNI]
        B -->|Apple Platforms| D[Secp256k1Pure]
    end

    subgraph "Pure Kotlin Logic"
        D --> E[Point Arithmetic]
        D --> F[Schnorr Signatures]
        D --> G[ECDH]
    end
```

---

## ✨ Features
- **Pure Kotlin for Apple**: Completely eliminates the need for complex C-interop on iOS and WatchOS.
- **Schnorr Support**: Full BIP340 implementation.
- **JNI for Speed**: Uses original C library on Android/JVM for maximum performance.
- **Unified API**: Identical interface regardless of the underlying implementation.

---

## 📦 Installation

```kotlin
// build.gradle.kts
implementation("com.github.ImL1s:kotlin-secp256k1-kmp:0.23.0-watchos")
```

---

## 📄 License
MIT License
