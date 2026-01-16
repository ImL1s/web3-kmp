package foundation.metaplex.rpc.networking

import com.solana.networking.HttpRequest
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertNotNull

data class MockHttpRequest(
    override val url: String,
    override val method: String,
    override val properties: Map<String, String>,
    override val body: String?,
) : HttpRequest

class NetworkingTests {
    companion object {
        private fun shouldRunIntegrationTests(): Boolean {
            return System.getenv("SOLANA_RPC_ENABLED") == "true"
        }
    }

    @Test
    fun testNetworkingHttpRequest() = runTest {
        if (!shouldRunIntegrationTests()) {
            println("Skipping: Set SOLANA_RPC_ENABLED=true to run")
            return@runTest
        }
        val networkDriver = NetworkDriver()
        val request = MockHttpRequest(
            "https://api.mainnet-beta.solana.com/",
            "get",
            mapOf("html" to "Content-Type"),
            "echo"
        )
        val response = networkDriver.makeHttpRequest(request)
        assertNotNull(response)
    }
}