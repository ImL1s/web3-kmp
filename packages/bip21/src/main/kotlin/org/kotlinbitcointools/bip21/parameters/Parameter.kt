/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

/**
 * All parameters that can be included in a BIP-21 URI must have a key and a value, and this interface ensures that we
 * can always encode them to a string in the format that is required by the BIP-21 specification.
 *
 * Note that the BIP-21 specification requires strings for query components be sanitized to make them safe to include in
 * URIs. Moreover, the percent-encoded space (%20) must be used as per RFC 3986 instead of the sometimes-used '+'
 * character.
 */
public interface Parameter {
    public fun encode(): String
}
