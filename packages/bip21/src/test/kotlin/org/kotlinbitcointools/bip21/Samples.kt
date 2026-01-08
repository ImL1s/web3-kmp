/*
 * Copyright 2023-2025 Kotlin Bitcoin Tools contributors.
 * Use of this source code is governed by the Apache 2.0 license that can be found in the ./LICENSE.txt file.
 */

package org.kotlinbitcointools.bip21

import org.kotlinbitcointools.bip21.parameters.Amount
import org.kotlinbitcointools.bip21.parameters.Label
import org.kotlinbitcointools.bip21.parameters.Message

fun buildBip21URIWithAnAddress() {
    val address: String = "1andreas3batLhQa2FawWjeyjCqyBzypd"
    val bip21Uri = Bip21URI(address)

    // Bip21URI(address=1andreas3batLhQa2FawWjeyjCqyBzypd, amount=null, label=null, message=null, lightning=null, pj=null, pjos=null, otherParameters=null)
    println(bip21Uri)

    // bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd
    println(bip21Uri.toURI())
}

fun buildComplexUri() {
    val bip21URI =
        Bip21URI(
            address = "1andreas3batLhQa2FawWjeyjCqyBzypd",
            amount = Amount(1000L),
            label = Label("Luke"),
            message = Message("Donation for project xyz"),
        )

    println(bip21URI.toURI())
    // bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=0.00001&label=Luke%2DJr&message=Donation%20for%20project%20xyz
}

fun decodeBip21URI() {
    val uri =
        Bip21URI.fromUri(
            "bitcoin:1andreas3batLhQa2FawWjeyjCqyBzypd?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz",
        )

    println(uri)
    // Bip21URI(address=1andreas3batLhQa2FawWjeyjCqyBzypd, amount=Amount(value=1000), label=Label(value=Luke-Jr), message=Message(value=Donation for project xyz), lightning=null, pj=null, pjos=null, otherParameters=null)
}
