# Using the bip21 library

The library is centered around the [`Bip21URI`](./api/bip21/org.bitcointools.bip21/-bip21-u-r-i/index.html) type, which offers two main functions: 

1. `Bip21URI.toURI(): String`. Note that this method will produce a string ready for QR encoding, but not optimal for human-readability (for example, URLs are percent-encoded). Use the `Bip21URI.toString()` instead for printing and debugging, or access the fields directly on the object.  
- `Bip21URI.fromURI(input: String): Bip21URI`. Use this method when reading raw string input from a QR code to parse and produce a typesafe `Bip21URI` object.

The `Bip21URI` type is a data class with typesafe fields for each of the standard BIP-21 URI parameters: `Amount`, `Label`, `Message`, `Lightning`, `PayJoin`, and other unknown parameters (`OtherParameter`).

For more examples on how to use the library, take a look at the [test suite] as well as the [samples in the API documentation].

[test suite]: https://github.com/kotlin-bitcoin-tools/bip21/tree/master/src/commonTest/kotlin/org/kotlinbitcointools/bip21/
[samples in the API documentation]: ./api/bip21/org.kotlinbitcointools.bip21/-bip21-u-r-i/index.html
