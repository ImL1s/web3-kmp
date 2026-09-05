package io.github.iml1s.client

import io.github.iml1s.client.bitcoin.ElectrumClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertEquals

class ElectrumIdPairingTest {

    @Test
    fun pairsResponsesByIdNotArrivalOrder() = runBlocking {
        val server = ServerSocket(0)
        val port = server.localPort
        val serverJob = async(Dispatchers.IO) {
            val sock = server.accept()
            val reader = BufferedReader(InputStreamReader(sock.getInputStream()))
            val writer = PrintWriter(sock.getOutputStream(), true)
            val line1 = reader.readLine()
            val line2 = reader.readLine()
            val id1 = Regex("\"id\":(\\d+)").find(line1)!!.groupValues[1]
            val id2 = Regex("\"id\":(\\d+)").find(line2)!!.groupValues[1]
            writer.println("""{"jsonrpc":"2.0","id":$id2,"result":{"confirmed":2,"unconfirmed":0}}""")
            delay(50)
            writer.println("""{"jsonrpc":"2.0","id":$id1,"result":{"confirmed":1,"unconfirmed":0}}""")
            sock.close()
            server.close()
        }

        val client = ElectrumClient("127.0.0.1", port, ssl = false)
        client.connect()
        val first = async { client.getBalance("aa") }
        delay(30)
        val second = async { client.getBalance("bb") }
        val r1 = first.await() as JsonObject
        val r2 = second.await() as JsonObject
        client.close()
        serverJob.await()
        assertEquals(1, r1["result"]!!.jsonObject["confirmed"]!!.jsonPrimitive.int)
        assertEquals(2, r2["result"]!!.jsonObject["confirmed"]!!.jsonPrimitive.int)
    }
}
