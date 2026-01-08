package io.github.iml1s.client.bitcoin

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.network.tls.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import kotlinx.serialization.json.*

class ElectrumClient(val host: String, val port: Int, val ssl: Boolean = false) {
    private var socket: Socket? = null
    private var readChannel: ByteReadChannel? = null
    private var writeChannel: ByteWriteChannel? = null
    private val selectorManager = SelectorManager(Dispatchers.IO)
    private var msgId = 0

    suspend fun connect() {
        val socketBuilder = aSocket(selectorManager).tcp()
        val rawSocket = socketBuilder.connect(host, port)
        
        socket = if (ssl) {
            rawSocket.tls(Dispatchers.IO)
        } else {
            rawSocket
        }
        
        readChannel = socket!!.openReadChannel()
        writeChannel = socket!!.openWriteChannel(autoFlush = true)
    }

    suspend fun close() {
        withContext(Dispatchers.IO) {
            socket?.close()
            selectorManager.close()
        }
    }

    suspend fun getBalance(scriptHash: String): JsonElement {
        // Expects full response object
        return requestFull("blockchain.scripthash.get_balance", JsonArray(listOf(JsonPrimitive(scriptHash))))
    }

    suspend fun listUnspent(scriptHash: String): JsonElement {
        // Expects result (JsonArray)
        return requestResult("blockchain.scripthash.listunspent", JsonArray(listOf(JsonPrimitive(scriptHash))))
    }

    suspend fun broadcastTransaction(txHex: String): JsonElement {
        // Expects result (JsonPrimitive)
        return requestResult("blockchain.transaction.broadcast", JsonArray(listOf(JsonPrimitive(txHex))))
    }

    private suspend fun requestFull(method: String, params: JsonArray): JsonObject {
        val id = msgId++
        val request = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", id)
            put("method", method)
            put("params", params)
        }
        
        val requestString = request.toString() + "\n"
        writeChannel?.writeStringUtf8(requestString)
        
        val responseLine = readChannel?.readUTF8Line() ?: throw Exception("Connection closed")
        return Json.parseToJsonElement(responseLine).jsonObject
    }
    
    private suspend fun requestResult(method: String, params: JsonArray): JsonElement {
        val response = requestFull(method, params)
        if (response.containsKey("error")) {
             throw Exception("Electrum Error: ${response["error"]}")
        }
        return response["result"] ?: JsonNull
    }
}
