# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-01-05
### Added
- **Sr25519 (Schnorrkel)**: Full support for Polkadot/Substrate signing scheme
  - **Merlin Transcript**: Strobe-128 protocol with exact rate/padding compatibility
  - **Ristretto255**: RFC 9496 compliant arithmetic
  - **Verification**: Validated against Polkadot-JS official test vectors
- **MuSig2**: BIP-327 Schnorr multi-signature aggregation and signing
- **Advanced Crypto**:
  - **BIP32-Ed25519**: Khovratovich derivation scheme (Cardano HD)
  - **SHA3**: Pure Kotlin implementation (SHA3-256, SHA3-512)
  - **SHA512**: Unified cross-platform implementation
- **New Chain Support**:
  - **Cardano (ADA)**: Shelley address generation (Base & Enterprise), Bech32, HD Wallets
  - **Polkadot (DOT)**: SS58 address encoding/decoding
  - **Ripple (XRP)**: Custom Base58 alphabet + double SHA256 checksum
  - **Cosmos (ATOM)**: Bech32 address generation
  - **Avalanche**: C-Chain (EVM) and X-Chain (Bech32) support
  - **Near Protocol**: Ed25519 hex addresses
  - **Sui**: Blake2b-256 addresses
  - **Aptos**: SHA3-256 addresses

## [1.2.0] - 2026-01-04
### Added
- **TON (The Open Network)**: Full support
  - Mnemonic-based KeyPair derivation (Ed25519)
  - Wallet V4R2 address generation
  - CRC16-CCITT checksum
- **PBKDF2**: Generalized support for custom iteration counts

## [1.1.0] - 2026-01-03

### Added
- **Bech32 & Bech32m**: Support for BIP 173 and BIP 350
  - Fully verified with official long test vectors (90 characters)
  - Optimized checksum calculation for long strings
- **Solana Support**: Address generation and Keypair utilities
  - Pure Kotlin Ed25519 key generation
  - Base58 address encoding
- **Tron Support**: Address generation
  - PubKey to Address (T-prefix) via Keccak256 and Base58Check
- **Hex Utility**: Unified and optimized hex encoding/decoding
  - Consolidated redundant helpers from `Bip32`, `Base58`, and `PureEthereumCrypto`
- **UInt Extensions**: Shared `toBigEndianByteArray` helper

### Fixed
- **BigInteger**: Resolved `NoSuchElementException` in `toByteArray()` for zero magnitude values
- **Bech32m Precision**: Fixed checksum calculation overflow on JVM using `Long`
- **Base58 Checksum**: Removed redundant and inconsistent implementations

### Changed
- Refactored `Bip32` and `PureEthereumCrypto` for better utility use and architectural consistency


## [1.0.0] - 2024-12-27

### Added

- **BIP39**: Mnemonic generation, validation, and seed derivation
  - Support for 12, 15, 18, 21, and 24-word mnemonics
  - Official Trezor test vectors verified
  - NFKD Unicode normalization

- **BIP32**: HD wallet key derivation
  - Hardened and non-hardened derivation paths
  - Public key derivation from xpub
  - Test Vectors 1, 2, 3 verified

- **Secp256k1**: Pure Kotlin ECDSA implementation
  - RFC 6979 deterministic signatures
  - Signature verification
  - ECDH key exchange
  - Wycheproof edge case tests

- **PBKDF2-HMAC-SHA512**: Key derivation
  - 2048 iterations (BIP39 compliant)
  - Platform-optimized implementations

- **AES-GCM**: Authenticated encryption
  - 256-bit key support
  - Secure nonce generation

- **Hashing**: Multiple algorithms
  - SHA256, SHA512
  - Keccak256 (Ethereum)
  - RIPEMD160 (Bitcoin)

- **Encoding**
  - Base58 with checksum
  - RLP (Recursive Length Prefix)

### Platforms

- Android (API 26+)
- iOS (arm64, x64, simulator)
- watchOS (arm64, x64, simulator)
- wearOS (via Android)

[1.0.0]: https://github.com/ImL1s/kotlin-crypto-pure/releases/tag/v1.0.0
