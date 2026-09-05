# web3-kmp

Kotlin Multiplatform libraries for Bitcoin, EVM, and Solana: cryptography, addresses, PSBT / transaction building, UTXO selection, CAIP identifiers, RPC clients, and platform-backed secret storage.

<p>
  <a href="https://github.com/ImL1s/web3-kmp/releases/tag/v1.3.1"><img src="https://img.shields.io/github/v/release/ImL1s/web3-kmp" alt="GitHub release"></a>
  <a href="https://github.com/ImL1s/web3-kmp/actions/workflows/ci.yml"><img src="https://github.com/ImL1s/web3-kmp/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://jitpack.io/#ImL1s/web3-kmp"><img src="https://jitpack.io/v/ImL1s/web3-kmp.svg" alt="JitPack"></a>
  <a href="#"><img src="https://img.shields.io/badge/kotlin-2.1.0-blue.svg?logo=kotlin" alt="Kotlin 2.1.0"></a>
  <a href="#"><img src="https://img.shields.io/badge/targets-JVM%20%7C%20Android%20%7C%20iOS%20%7C%20watchOS-orange" alt="Targets"></a>
</p>

Latest tag: **[v1.3.1](https://github.com/ImL1s/web3-kmp/releases/tag/v1.3.1)** (2026-09-05). Maven Central is not the ship path. Consume GitHub tags via [JitPack](https://jitpack.io/#ImL1s/web3-kmp), clone this repo, or use the extracted standalone libraries below.

This is a **monorepo**, not a single artifact. Gradle `group` is `io.github.iml1s` for the ImL1s packages. Targets vary by package (typical: JVM, Android, iOS, watchOS) — see each `packages/*/build.gradle.kts`.

## Standalone libraries

These packages also ship as smaller repos with simpler JitPack coordinates (tag **v1.0.1** on each):

| Library | Repo | Coordinate |
|---------|------|------------|
| Pure Kotlin crypto (BIP32/39, secp256k1, …) | [kotlin-crypto-pure](https://github.com/ImL1s/kotlin-crypto-pure) | `com.github.ImL1s:kotlin-crypto-pure:1.0.1` |
| Bitcoin / EVM / Solana addresses | [kotlin-address](https://github.com/ImL1s/kotlin-address) | `com.github.ImL1s:kotlin-address:1.0.1` |
| Bitcoin + EVM tx / PSBT builder | [kotlin-tx-builder](https://github.com/ImL1s/kotlin-tx-builder) | `com.github.ImL1s:kotlin-tx-builder:1.0.1` |
| CAIP-2 / CAIP-10 / CAIP-19 | [kotlin-caip-standards](https://github.com/ImL1s/kotlin-caip-standards) | `com.github.ImL1s:kotlin-caip-standards:1.0.1` |

```kotlin
// settings.gradle.kts / build.gradle.kts
repositories {
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.ImL1s:kotlin-crypto-pure:1.0.1")
    implementation("com.github.ImL1s:kotlin-address:1.0.1")
    implementation("com.github.ImL1s:kotlin-tx-builder:1.0.1")
    implementation("com.github.ImL1s:kotlin-caip-standards:1.0.1")
}
```

This tree is the integration monorepo (shared Gradle, examples, and packages that are not extracted). Monorepo package versions are not always the same number as the standalone tag.

## Packages in this repo

| Package | Gradle project | Version | Role |
|---------|----------------|---------|------|
| [crypto-pure](packages/crypto-pure) | `:packages:crypto-pure` / `:packages:crypto-pure:crypto-core` | 1.3.1 | Pure Kotlin primitives (secp256k1, BIP32, hashes, RLP, …) |
| [address](packages/address) | `:packages:address` | 1.3.1 | Multi-chain address encode / validate (Bech32, EIP-55, …) |
| [tx-builder](packages/tx-builder) | `:packages:tx-builder` | 1.3.1 | Bitcoin (BIP143, PSBT v0) and EVM (EIP-1559) transaction building |
| [utxo](packages/utxo) | `:packages:utxo` | 1.3.1 | UTXO coin selection (branch-and-bound, `maxInputs`) |
| [blockchain-client](packages/blockchain-client) | `:packages:blockchain-client` | 1.3.1 | Chain RPC helpers (EVM wei as decimal string; Electrum id pairing) |
| [caip-standards](packages/caip-standards) | `:packages:caip-standards` | 1.0.1 | CAIP-2 / 10 / 19 identifiers |
| [secure-storage](packages/secure-storage) | `:packages:secure-storage` | 1.0.1 | Platform secret storage (JVM AES-GCM vault is fail-closed) |
| [solana](packages/solana) | `:packages:solana` | 1.3.0 | Solana client modules (Metaplex license — see below) |
| [bitcoin](packages/bitcoin) | `:packages:bitcoin` | 0.30.0-SNAPSHOT | Bitcoin protocol (`fr.acinq.bitcoin`) |
| [secp256k1](packages/secp256k1) | `:packages:secp256k1` | 0.23.0-SNAPSHOT | Native secp256k1 JNI (`fr.acinq.secp256k1`) |
| [miniscript](packages/miniscript) | `:packages:miniscript` | 1.0.0 | Bitcoin Miniscript |
| [hardware-wallet](packages/hardware-wallet) | `:packages:hardware-wallet` | 1.0.0 | Hardware-wallet interfaces |
| [bip21](packages/bip21) | `:packages:bip21` | 0.1.0-SNAPSHOT | BIP21 URIs (`org.kotlinbitcointools`) |
| bitkey | `:packages:bitkey` | — | Included in settings; source is not populated in this tree |

Example app: [`examples/bitcoin-wallet`](examples/bitcoin-wallet).

## Use this monorepo locally

```kotlin
// settings.gradle.kts of a consumer
includeBuild("../web3-kmp")
```

Or `./gradlew publishToMavenLocal` and depend on `io.github.iml1s:<package>:<version>` from the table above.

JitPack can build tag `v1.3.1` of this repo; module names follow Gradle projects under `packages/`. Prefer the standalone coordinates when you only need crypto / address / tx-builder / CAIP.

## Build and test

JDK 17. GitHub Actions on `master` runs the P1 `jvmTest` set (25-minute timeout), not a full `assemble` of bitcoin / solana / native:

```bash
./gradlew \
  :packages:secure-storage:jvmTest \
  :packages:utxo:jvmTest \
  :packages:blockchain-client:jvmTest \
  :packages:crypto-pure:crypto-core:jvmTest \
  :packages:address:jvmTest \
  :packages:tx-builder:jvmTest \
  :packages:caip-standards:jvmTest
```

`./gradlew build` / `check` exercises the whole tree and is much heavier.

## Correctness (v1.3.1)

P1 fixes in `secure-storage`, `crypto-pure` / `crypto-core`, `address`, `tx-builder`, `caip-standards`, `utxo`, and `blockchain-client` (fail-closed vault, BIP143 / PSBT / chainId bytes, CAIP / UTXO / wei validity). See [CHANGELOG](CHANGELOG.md).

This is **not** a full seven-library API security certification. Remaining public APIs are NOT_RUN. Apple Keychain, Android Keystore, bitcoind, and local EVM submit were not exercised in the v1.3.1 environment.

## License

There is no single root license. Check each package:

- Apache-2.0: `crypto-pure`, `caip-standards`, `utxo`, `bitcoin`, `secp256k1`, `bip21`
- [Metaplex NFT Open Source License](packages/solana/LICENSE.txt): `solana`
- Other packages: see their directory (some have no `LICENSE` file yet)

## Links

- [GitHub Releases](https://github.com/ImL1s/web3-kmp/releases)
- [CHANGELOG](CHANGELOG.md)
- [JitPack](https://jitpack.io/#ImL1s/web3-kmp)
- [CI](https://github.com/ImL1s/web3-kmp/actions/workflows/ci.yml)
