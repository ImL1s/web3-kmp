package io.github.iml1s.client.zcash

import kotlinx.serialization.Serializable

@Serializable
data class ZcashUtxo(
    val txid: String? = null,
    val outputIndex: Int? = null,
    val valueZat: Long? = null,
    val script: String? = null
)
