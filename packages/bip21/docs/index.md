# About

!!! warning
    This library should be considered in alpha state. Please use with caution and consider helping to review it.


The `org.kotlinbitcointools.bip21` library is an implementation of the [BIP-0021 specification]. It is written in Kotlin and is intended to be used in Kotlin Multiplatform projects. Please help us review it and make it production-ready! Comments on the shape of the API are welcome. See the [issues] for discussion items and design decisions. The library is released under the Apache 2.0 license.

## Project Goals

The main goals of this library are:
       
  - [x] 1. Be BIP-21 compliant
    - [x] Encoding and decoding QR-ready strings
    - [x] Typesafe support for all standard parameters
    - [x] Unified QRs
    - [x] Payjoin
  - [x] 2. Well tested
  - [ ] 3. Well documented
  - [ ] 4. Production ready
  - [x] 5. Usable in KMP projects and supporting the following targets:
    - [x] JVM + Android
    - [x] iosArm64
    - [x] iosX64
    - [x] iosSimulatorArm64

[BIP-0021 specification]: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
[issues]: https://github.com/kotlin-bitcoin-tools/bip21/issues
