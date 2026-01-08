/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import io.ktor.http.encodeURLQueryComponent

/**
 * This class represents any other parameter not defined in the BIP-21 specification.
 *
 * @property key The key of the parameter.
 * @property value The value of the parameter.
 */
public data class OtherParameter(
    val key: String,
    val value: String,
) : Parameter {
    override fun encode(): String =
        "&${key.encodeURLQueryComponent(encodeFull = true)}=${value.encodeURLQueryComponent(encodeFull = true)}"
}
