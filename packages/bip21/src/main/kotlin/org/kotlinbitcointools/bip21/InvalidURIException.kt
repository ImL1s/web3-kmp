/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21

/**
 * This exception is thrown when a URI is invalid.
 */
public class InvalidURIException(
    message: String,
) : Exception(message)
