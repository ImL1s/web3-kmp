/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21.parameters

import io.ktor.http.encodeURLQueryComponent

/**
 * The lightning parameter.
 *
 * @property pr The payment request.
 */
public data class Lightning(
    val pr: String,
) : Parameter {
    override fun encode(): String = "&lightning=${pr.encodeURLQueryComponent(encodeFull = true)}"
}
