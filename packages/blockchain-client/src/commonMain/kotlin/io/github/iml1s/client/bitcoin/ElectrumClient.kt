package io.github.iml1s.client.bitcoin

import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import io.ktor.network.tls.*
import io.ktor.utils.io.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*

class ElectrumClient(val host: String, val port: Int, val ssl: Boolean = false) {
    private var socket: Socket? = null
    private var readChannel: ByteReadChannel? = null
    private var writeChannel: ByteWriteChannel? = null
    private val selectorManager = SelectorManager(Dispatchers.IO)
    private var msgId = 0
    private val pending = mutableMapOf<Int, CompletableDeferred<JsonObject>>()
    private val mutex = Mutex()
    private var readerJob: Job? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

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
        readerJob = scope.launch { readLoop() }
    }

    suspend fun close() {
        readerJob?.cancel()
        withContext(Dispatchers.IO) {
            socket?.close()
            selectorManager.close()
        }
        scope.cancel()
    }

    suspend fun getBalance(scriptHash: String): JsonElement {
        return requestFull("blockchain.scripthash.get_balance", JsonArray(listOf(JsonPrimitive(scriptHash))))
    }

    suspend fun listUnspent(scriptHash: String): JsonElement {
        return requestResult("blockchain.scripthash.listunspent", JsonArray(listOf(JsonPrimitive(scriptHash))))
    }

    suspend fun broadcastTransaction(txHex: String): JsonElement {
        return requestResult("blockchain.transaction.broadcast", JsonArray(listOf(JsonPrimitive(txHex))))
    }

    private suspend fun readLoop() {
        try {
            while (true) {
                val responseLine = readChannel?.readUTF8Line() ?: break
                val obj = Json.parseToJsonElement(responseLine).jsonObject
                val idEl = obj["id"]
                val id = (idEl as? JsonPrimitive)?.intOrNull
                if (id != null) {
                    val waiter = mutex.withLock { pending.remove(id) }
                    waiter?.complete(obj)
                }
            }
        } catch (_: Exception) {
            mutex.withLock {
                pending.values.forEach { it.completeExceptionally(Exception("Electrum connection closed")) }
                pending.clear()
            }
        }
    }

    private suspend fun requestFull(method: String, params: JsonArray): JsonObject {
        val id = mutex.withLock { msgId++ }
        val deferred = CompletableDeferred<JsonObject>()
        mutex.withLock { pending[id] = deferred }
        val request = buildJsonObject {
            put("jsonrpc", "2.0")
            put("id", id)
            put("method", method)
            put("params", params)
        }
        writeChannel?.writeStringUtf8(request.toString() + "\n")
        return withTimeout(30_000) { deferred.await() }
    }

    private suspend fun requestResult(method: String, params: JsonArray): JsonElement {
        val response = requestFull(method, params)
        if (response.containsKey("error")) {
            throw Exception("Electrum Error: ${response["error"]}")
        }
        return response["result"] ?: JsonNull
    }
}
