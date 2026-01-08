# BIP-21 (Kotlin)

<p align="center">
  <img src="../docs/images/kmp_crypto_banner.png" alt="BIP-21" width="100%">
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin"></a>
  <a href="#"><img src="https://img.shields.io/badge/status-experimental-orange" alt="Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

> [!WARNING]
> This library is not currently production-ready. Use at your own risk.

---

## 🏗️ URI Parsing Flow

```mermaid
graph LR
    STR[Raw URI String] --> P[BitcoinURI Parser]
    
    subgraph "Extracted Components"
        P --> ADDR[Bitcoin Address]
        P --> AMNT[Amount in BTC]
        P --> LBL[Label / Message]
        P --> EXT[Custom Parameters]
    end
    
    EXT --> BAL[Balance Check / Validation]
```

---

## Goals

- [x] BIP-0021 compliant
- [x] Well tested
- [ ] Well documented
- [ ] Production ready
- [ ] Usable in KMP projects (JVM and iOS platforms)

## Install

The library is currently deployed to Maven Central's snapshot repository.

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots/")
    }
}
```

```kotlin
// build.gradle.kts
implementation("org.kotlinbitcointools:bip21:0.0.5-SNAPSHOT")
```

## Documentation

You can [find the docs for this library here](https://kotlin-bitcoin-tools.github.io/bip21/index.html).

## Build locally

```shell
./gradlew publishToMavenLocal
```

[BIP-0021]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
