package io.github.iml1s.client.monero

import io.ktor.client.*

class MoneroDaemonClient(val httpClient: HttpClient, val url: String) {

    suspend fun getBlockHeight(): Long {
        // Placeholder
        return 0L
    }
}
