# web3-kmp

A comprehensive Kotlin Multiplatform library collection for blockchain and Web3 development.

## 📦 Packages

This monorepo contains the following packages:

### Core Cryptography
- **secp256k1** - Elliptic curve cryptography (secp256k1)
- **crypto-pure** - Pure Kotlin cryptographic primitives

### Bitcoin & UTXO
- **bitcoin** - Bitcoin protocol implementation
- **utxo** - UTXO management
- **tx-builder** - Transaction builder for Bitcoin and other UTXO chains
- **miniscript** - Bitcoin Miniscript support

### Address & Key Management
- **address** - Multi-chain address generation and validation
- **secure-storage** - Platform-native secure storage

### Blockchain Clients
- **blockchain-client** - Generic blockchain RPC client
- **solana** - Solana blockchain support

### Standards & Utilities
- **caip-standards** - Chain Agnostic Improvement Proposals (CAIP) standards
- **bip21** - BIP21 URI scheme support
- **bitkey** - Hardware wallet integration (Bitkey)
- **hardware-wallet** - Generic hardware wallet support

## Correctness (v1.3.1)

P1 fixes in `secure-storage`, `crypto-pure`/`crypto-core`, `address`, `tx-builder`, `caip-standards`, `utxo`, and `blockchain-client` (fail-closed vault, BIP143/PSBT/chainId bytes, CAIP/UTXO/wei validity). See [CHANGELOG](CHANGELOG.md). This is not a full seven-library API security certification; remaining public APIs are NOT_RUN.

## 🏗️ Building

```bash
./gradlew build
```

## ✅ Testing

```bash
./gradlew check
```

## 📄 License

Each package may have its own license. Please refer to individual package directories for details.

## 🔗 Links

- [GitHub Repository](https://github.com/ImL1s/web3-kmp)
