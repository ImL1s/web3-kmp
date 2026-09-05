# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-09-05

P1 correctness slice on the issue-specified packages. This is **not** a full seven-library API security certification; unmarked public APIs remain NOT_RUN.

### Fixed

- **secure-storage**: JVM vault decrypt/format/auth failure is fail-closed (not treated as empty; a later put cannot overwrite a still-present corrupt vault). Native backend throws rather than reporting put-success while get is always null. Keychain `clear` is service-scoped.
- **crypto-pure / crypto-core**: `pubKeyOf` does not interpolate private-key bytes; secp256k1 identity is infinity not affine `(0,0)`; RFC 6979 uses `bits2octets`; strict DER; BIP32 `IL>=n` rejected before add; RLP of a negative integer is not `0x80`.
- **address**: Bech32 mixed case and invalid HRP / witness-program lengths rejected.
- **tx-builder**: BIP143 P2WPKH scriptCode CompactSize once (official sighash `c37af311…`); legacy/Taproot hash-type rules; PSBT v0 unsigned tx + typed maps including final script witness `0x08` and proprietary `0xFC`; missing EIP-1559 `chainId` is an error.
- **caip-standards**: `Success(false)` is invalid; non-finite amounts rejected; `::` is not an address; NFT asset ids round-trip; unknown network is not mainnet (`sepolia` → `eip155:11155111`).
- **utxo**: Branch-and-bound respects `maxInputs`; selection conservation / unique outpoints.
- **blockchain-client**: EVM `10^19` wei is a decimal string uint256 (not `Long`); Electrum JSON-RPC pairs responses by id.

Apple Keychain / Android Keystore / bitcoind / local EVM submit remain NOT_RUN in this environment.

[1.3.1]: https://github.com/ImL1s/web3-kmp/releases/tag/v1.3.1
