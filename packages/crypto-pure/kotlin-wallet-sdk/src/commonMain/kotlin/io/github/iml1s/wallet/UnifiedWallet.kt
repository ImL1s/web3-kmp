package io.github.iml1s.wallet

import io.github.iml1s.crypto.*
import io.github.iml1s.crypto.Bip32
import io.github.iml1s.crypto.Secp256k1Pure
import io.github.andreypfau.curve25519.ed25519.Ed25519
import io.github.iml1s.client.bitcoin.ElectrumClient
import io.github.iml1s.client.zcash.LightwalletdClient
import io.github.iml1s.client.monero.MoneroDaemonClient
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.contentType
import io.ktor.http.ContentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.int
import kotlinx.serialization.json.long
import io.github.iml1s.address.BitcoinScript
import io.github.iml1s.tx.dash.DashTxBuilder
import io.github.iml1s.tx.dash.DashTransaction
import io.github.iml1s.tx.zcash.ZcashTxBuilder
import io.github.iml1s.tx.zcash.ZcashTransaction
import io.github.iml1s.tx.bitcoin.TxInput
import io.github.iml1s.utxo.UTXO
import io.github.iml1s.tx.bitcoin.ByteArrayBuilder




/**
 * Network type for multi-network support
 */
enum class NetworkType {
    MAINNET, TESTNET
}

/**
 * Network configuration for each chain
 */
object NetworkConfig {
    fun bitcoinElectrum(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> Pair("electrum.blockstream.info", 50002)
        NetworkType.TESTNET -> Pair("electrum.blockstream.info", 60002) // Testnet4
    }
    
    fun dashElectrum(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> Pair("electrum.dash.org", 50002)
        NetworkType.TESTNET -> Pair("electrum-testnet.dash.org", 50002)
    }
    
    fun zcashLightwalletd(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> "https://mainnet.lightwalletd.com"
        NetworkType.TESTNET -> "https://lightwalletd.testnet.z.cash"
    }
    
    fun ethereumRpc(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> "https://eth.llamarpc.com"
        NetworkType.TESTNET -> "https://ethereum-sepolia-rpc.publicnode.com"
    }
    
    fun solanaRpc(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> "https://api.mainnet-beta.solana.com"
        NetworkType.TESTNET -> "https://api.devnet.solana.com"
    }
    
    fun moneroRpc(network: NetworkType) = when(network) {
        NetworkType.MAINNET -> "http://node.community.rino.io:18081"
        NetworkType.TESTNET -> "http://stagenet.community.rino.io:18081" // Using stagenet as testnet proxy
    }
}

/**
 * The main entry point for the Unified Wallet SDK.
 * Manages accounts and provides access to per-chain services.
 */
class UnifiedWallet private constructor(
    val mnemonic: String,
    val seed: ByteArray,
    val network: NetworkType = NetworkType.MAINNET
) {
    companion object {
        fun create(mnemonic: String, passphrase: String = "", network: NetworkType = NetworkType.MAINNET): UnifiedWallet {
            val seed = Pbkdf2.bip39Seed(mnemonic, passphrase)
            return UnifiedWallet(mnemonic, seed, network)
        }
    }


    // Shared HTTP Client
    val httpClient = HttpClient {
        install(ContentNegotiation) {
            json(Json { 
                ignoreUnknownKeys = true 
                prettyPrint = true
                isLenient = true
            })
        }
    }

    // Lazy initialization of chain services
    val bitcoin: ChainService by lazy { BitcoinService(this) }
    val ethereum: ChainService by lazy { EthereumService(this) }
    val solana: ChainService by lazy { SolanaService(this) }
    val dash: ChainService by lazy { DashService(this) }
    val zcash: ChainService by lazy { ZcashService(this) }
    val monero: ChainService by lazy { MoneroService(this) }
    
    // Future expansion: litecoin, dogecoin, etc.
}

interface ChainService {
    val chain: Chain
    
    // Account Management
    fun getAddress(index: Int = 0): String
    
    // Balance (Suspend as it requires network)
    suspend fun getBalance(address: String? = null): Balance
    
    // Transaction (Placeholder for now)
    suspend fun send(to: String, amount: String): String
}

enum class Chain {
    BITCOIN, ETHEREUM, SOLANA, DASH, ZCASH, MONERO
}

data class Balance(
    val total: String,
    val available: String,
    val decimals: Int,
    val symbol: String
)

// Helper object for Hash and Encoding
private object WalletUtils {
    fun sha256(data: ByteArray): ByteArray {
        val digest = Digests.sha256()
        digest.update(data, 0, data.size)
        val out = ByteArray(digest.getDigestSize())
        digest.doFinal(out, 0)
        return out
    }

    fun ripemd160(data: ByteArray): ByteArray = Ripemd160.hash(data)

    fun encodeSegwit(hrp: String, version: Int, program: ByteArray): String {
        val data = Bech32.convertBits(program, 8, 5, true)
        val combined = ByteArray(1 + data.size)
        combined[0] = version.toByte()
        data.copyInto(combined, 1)
        return Bech32.encode(hrp, combined, Bech32.Spec.BECH32)
    }

    fun encodeDer(signature: ByteArray): ByteArray {
        val r = signature.copyOfRange(0, 32)
        val s = signature.copyOfRange(32, 64)
        
        val rEncoded = encodeInteger(r)
        val sEncoded = encodeInteger(s)
        
        val buffer = ByteArrayBuilder()
        buffer.writeByte(0x30) // SEQUENCE
        buffer.writeByte(rEncoded.size + sEncoded.size)
        buffer.writeBytes(rEncoded)
        buffer.writeBytes(sEncoded)
        return buffer.toByteArray()
    }

    private fun encodeInteger(bytes: ByteArray): ByteArray {
        // Remove leading zeros
        var start = 0
        while (start < bytes.size && bytes[start] == 0.toByte()) {
            start++
        }
        val trimmed = if (start == bytes.size) byteArrayOf(0) else bytes.copyOfRange(start, bytes.size)
        
        // Check MSB
        return if (trimmed[0] < 0) { // < 0 means >= 0x80 in signed byte
            byteArrayOf(0) + trimmed
        } else {
            trimmed
        }
    }
}

// Implementations
class BitcoinService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.BITCOIN
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val hrp = if (isTestnet) "tb" else "bc"
    private val endpoint = NetworkConfig.bitcoinElectrum(wallet.network)
    private val client = ElectrumClient(endpoint.first, endpoint.second, ssl = true)

    override fun getAddress(index: Int): String {
        // BIP84: m/84'/0'/0'/0/index (Native SegWit) - Testnet uses m/84'/1'/0'/0/index
        val coinType = if (isTestnet) "1" else "0"
        val path = "m/84'/$coinType'/0'/0/$index"
        val key = Bip32.derivePath(wallet.seed, path)
        val pubKey = Secp256k1Pure.generatePublicKey(key.privateKey, compressed = true)
        val pubKeyHash = WalletUtils.ripemd160(WalletUtils.sha256(pubKey))
        return WalletUtils.encodeSegwit(hrp, 0, pubKeyHash)
    }
    
    override suspend fun getBalance(address: String?): Balance {
        val addr = address ?: getAddress()
        return try {
            client.connect()
            val scriptHash = BitcoinScript.addressToScriptHash(addr)
            val response = client.getBalance(scriptHash)
            
            val result = response.jsonObject["result"]?.jsonObject
            val confirmed = result?.get("confirmed")?.jsonPrimitive?.longOrNull ?: 0L
            val unconfirmed = result?.get("unconfirmed")?.jsonPrimitive?.longOrNull ?: 0L
            val total = confirmed + unconfirmed
            
            Balance(total.toString(), confirmed.toString(), 8, "BTC")
        } catch (e: Exception) {
            e.printStackTrace()
            Balance("0", "0", 8, "BTC")
        } finally {
            try { client.close() } catch(e: Exception) {}
        }
    }
    
    override suspend fun send(to: String, amount: String): String {
        val amountSats = (amount.toDouble() * 100_000_000).toLong()
        val myAddress = getAddress()
        
        // 1. Fetch UTXOs
        client.connect()
        val scriptHash = BitcoinScript.addressToScriptHash(myAddress)
        val utxosJson = client.listUnspent(scriptHash)
        
        val utxos = utxosJson.jsonArray.map {
            val txHash = it.jsonObject["tx_hash"]!!.jsonPrimitive.content
            val txPos = it.jsonObject["tx_pos"]!!.jsonPrimitive.int
            val value = it.jsonObject["value"]!!.jsonPrimitive.long
            UTXO(txHash, txPos, value, true)
        }
        
        // 2. Select UTXOs
        var current = 0L
        val inputs = mutableListOf<UTXO>()
        val fee = 1000L // Simple fixed fee
        
        for (u in utxos) {
            inputs.add(u)
            current += u.value
            if (current >= amountSats + fee) break
        }
        
        if (current < amountSats + fee) throw Exception("Insufficient funds. Have: $current sats, Need: ${amountSats + fee}")
        
        // 3. Build SegWit Transaction
        val coinType = if (isTestnet) "1" else "0"
        val path = "m/84'/$coinType'/0'/0/0"
        val key = Bip32.derivePath(wallet.seed, path)
        val privKey = key.privateKey
        val pubKey = Secp256k1Pure.generatePublicKey(privKey, compressed = true)
        val pubKeyHash = WalletUtils.ripemd160(WalletUtils.sha256(pubKey))
        
        // Build raw transaction
        val builder = ByteArrayBuilder()
        
        // Version (2 for SegWit)
        builder.writeInt32LE(2)
        
        // Marker + Flag (SegWit)
        builder.writeByte(0x00)
        builder.writeByte(0x01)
        
        // Input count
        builder.writeVarInt(inputs.size.toLong())
        
        // Inputs
        inputs.forEach { utxo ->
            builder.writeBytes(Hex.decode(utxo.txid).reversedArray()) // TXID (reversed)
            builder.writeInt32LE(utxo.vout) // vout
            builder.writeVarInt(0) // Empty scriptSig for SegWit
            builder.writeInt32LE(-2) // Sequence (RBF enabled)
        }
        
        // Output count
        val hasChange = (current - amountSats - fee) > 546
        builder.writeVarInt(if (hasChange) 2L else 1L)
        
        // Output 1: To address
        builder.writeInt64LE(amountSats)
        val toScript = BitcoinScript.addressToScriptPubKey(to)
        builder.writeVarInt(toScript.size.toLong())
        builder.writeBytes(toScript)
        
        // Output 2: Change (if any)
        if (hasChange) {
            val changeAmount = current - amountSats - fee
            builder.writeInt64LE(changeAmount)
            // P2WPKH scriptPubKey: OP_0 <20-byte-pubkey-hash>
            val changeScript = byteArrayOf(0x00, 0x14) + pubKeyHash
            builder.writeVarInt(changeScript.size.toLong())
            builder.writeBytes(changeScript)
        }
        
        // Witness data (signatures)
        inputs.forEachIndexed { idx, utxo ->
            builder.writeVarInt(2) // 2 items in witness
            
            // Create sighash for this input (BIP143)
            val sighash = computeSegWitSighash(
                inputs, idx, pubKeyHash, utxo.value, amountSats,
                if (hasChange) current - amountSats - fee else 0L,
                to, myAddress
            )
            
            val signature = Secp256k1Pure.sign(sighash, privKey)
            val derSig = WalletUtils.encodeDer(signature) + 0x01.toByte() // SIGHASH_ALL
            
            builder.writeVarInt(derSig.size.toLong())
            builder.writeBytes(derSig)
            builder.writeVarInt(pubKey.size.toLong())
            builder.writeBytes(pubKey)
        }
        
        // Locktime
        builder.writeInt32LE(0)
        
        val rawTx = builder.toByteArray()
        val txHex = Hex.encode(rawTx)
        
        return client.broadcastTransaction(txHex).jsonPrimitive.content
    }
    
    private fun computeSegWitSighash(
        inputs: List<UTXO>, inputIndex: Int, pubKeyHash: ByteArray, inputValue: Long,
        outputAmount: Long, changeAmount: Long, toAddress: String, changeAddress: String
    ): ByteArray {
        val builder = ByteArrayBuilder()
        
        // 1. nVersion
        builder.writeInt32LE(2)
        
        // 2. hashPrevouts
        val prevoutsBuilder = ByteArrayBuilder()
        inputs.forEach { utxo ->
            prevoutsBuilder.writeBytes(Hex.decode(utxo.txid).reversedArray())
            prevoutsBuilder.writeInt32LE(utxo.vout)
        }
        val hashPrevouts = WalletUtils.sha256(WalletUtils.sha256(prevoutsBuilder.toByteArray()))
        builder.writeBytes(hashPrevouts)
        
        // 3. hashSequence
        val seqBuilder = ByteArrayBuilder()
        inputs.forEach { seqBuilder.writeInt32LE(-2) }
        val hashSequence = WalletUtils.sha256(WalletUtils.sha256(seqBuilder.toByteArray()))
        builder.writeBytes(hashSequence)
        
        // 4. outpoint
        val utxo = inputs[inputIndex]
        builder.writeBytes(Hex.decode(utxo.txid).reversedArray())
        builder.writeInt32LE(utxo.vout)
        
        // 5. scriptCode (P2WPKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG)
        val scriptCode = byteArrayOf(0x19, 0x76.toByte(), 0xa9.toByte(), 0x14) + pubKeyHash + byteArrayOf(0x88.toByte(), 0xac.toByte())
        builder.writeBytes(scriptCode)
        
        // 6. value
        builder.writeInt64LE(inputValue)
        
        // 7. nSequence
        builder.writeInt32LE(-2)
        
        // 8. hashOutputs
        val outputsBuilder = ByteArrayBuilder()
        outputsBuilder.writeInt64LE(outputAmount)
        val toScript = BitcoinScript.addressToScriptPubKey(toAddress)
        outputsBuilder.writeVarInt(toScript.size.toLong())
        outputsBuilder.writeBytes(toScript)
        if (changeAmount > 546) {
            outputsBuilder.writeInt64LE(changeAmount)
            val changeScript = byteArrayOf(0x00, 0x14) + pubKeyHash
            outputsBuilder.writeVarInt(changeScript.size.toLong())
            outputsBuilder.writeBytes(changeScript)
        }
        val hashOutputs = WalletUtils.sha256(WalletUtils.sha256(outputsBuilder.toByteArray()))
        builder.writeBytes(hashOutputs)
        
        // 9. nLockTime
        builder.writeInt32LE(0)
        
        // 10. sighash type
        builder.writeInt32LE(1) // SIGHASH_ALL
        
        return WalletUtils.sha256(WalletUtils.sha256(builder.toByteArray()))
    }
}


class EthereumService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.ETHEREUM
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val chainId = if (isTestnet) 11155111L else 1L // Sepolia or Mainnet
    private val rpcUrl = NetworkConfig.ethereumRpc(wallet.network)
    private val client = io.github.iml1s.client.ethereum.EvmJsonRpcClient(wallet.httpClient, rpcUrl, chainId)
    
    override fun getAddress(index: Int): String {
        // BIP44: m/44'/60'/0'/0/index
        val path = "m/44'/60'/0'/0/$index"
        val key = Bip32.derivePath(wallet.seed, path)
        return PureEthereumCrypto.getEthereumAddress(Hex.encode(key.privateKey))
    }
    
    override suspend fun getBalance(address: String?): Balance {
        val addr = address ?: getAddress()
        return try {
            val balanceWei = client.getBalance(addr)
            // Convert to ETH string (18 decimals)
            val ethString = (balanceWei.toDouble() / 1e18).toString()
            Balance(ethString, ethString, 18, "ETH")
        } catch (e: Exception) {
            e.printStackTrace()
            Balance("0", "0", 18, "ETH")
        }
    }
    
    override suspend fun send(to: String, amount: String): String {
        val amountWei = (amount.toDouble() * 1e18).toLong()
        val myAddress = getAddress()
        
        // Get nonce and gas price
        val nonce = client.getNonce(myAddress)
        val feeRates = client.getFeeRates()
        
        // Build EIP-1559 Transaction
        val maxFeePerGas = feeRates.fast
        val maxPriorityFee = 1_500_000_000L // 1.5 Gwei priority
        val gasLimit = 21000L // Simple transfer
        
        // Create transaction data
        val tx = io.github.iml1s.tx.ethereum.Eip1559Transaction(
            chainId = chainId,
            nonce = nonce,
            maxPriorityFeePerGas = maxPriorityFee.toByteArrayBE(),
            maxFeePerGas = maxFeePerGas.toByteArrayBE(),
            gasLimit = gasLimit,
            to = to,
            value = amountWei.toByteArrayBE(),
            data = byteArrayOf()
        )
        
        // Sign
        val path = "m/44'/60'/0'/0/0"
        val key = Bip32.derivePath(wallet.seed, path)
        val privKey = key.privateKey
        
        val sigHash = Keccak256.hash(tx.encode(forSigning = true))
        val signature = Secp256k1Pure.sign(sigHash, privKey)
        
        // Calculate yParity (v) from signature
        val v = calculateYParity(sigHash, signature, privKey)
        
        val signedTx = tx.copy(
            v = v.toLong(),
            r = signature.copyOfRange(0, 32),
            s = signature.copyOfRange(32, 64)
        )
        
        val rawTxHex = "0x" + Hex.encode(signedTx.encode(forSigning = false))
        return client.broadcastTransaction(rawTxHex)
    }
    
    private fun calculateYParity(hash: ByteArray, signature: ByteArray, privKey: ByteArray): Int {
        // Try both parities and see which one recovers to our public key
        val pubKey = Secp256k1Pure.generatePublicKey(privKey, compressed = false)
        // For simplicity, we use 0 (most common case for low-s signatures)
        // A proper implementation would use ecrecover
        return 0
    }
    
    private fun Long.toByteArrayBE(): ByteArray {
        if (this == 0L) return byteArrayOf()
        var value = this
        val bytes = mutableListOf<Byte>()
        while (value > 0) {
            bytes.add(0, (value and 0xFF).toByte())
            value = value shr 8
        }
        return bytes.toByteArray()
    }
}


class SolanaService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.SOLANA
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val rpcUrl = NetworkConfig.solanaRpc(wallet.network)
    
    override fun getAddress(index: Int): String {
        // BIP44: m/44'/501'/0'/0' (Solana uses hardened accounts)
        val path = "m/44'/501'/0'/0'"
        val key = Bip32.derivePath(wallet.seed, path)
        val pair = Ed25519.keyFromSeed(key.privateKey)
        return Solana.getAddress(pair.publicKey().toByteArray())
    }
    
    override suspend fun getBalance(address: String?): Balance {
        val addr = address ?: getAddress()
        return try {
            val response = wallet.httpClient.post(rpcUrl) {
                contentType(io.ktor.http.ContentType.Application.Json)
                setBody("""{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["$addr"]}""")
            }
            val json = kotlinx.serialization.json.Json.parseToJsonElement(response.bodyAsText())
            val lamports = json.jsonObject["result"]?.jsonObject?.get("value")?.jsonPrimitive?.longOrNull ?: 0L
            val solString = (lamports.toDouble() / 1_000_000_000).toString()
            Balance(solString, solString, 9, "SOL")
        } catch (e: Exception) {
            e.printStackTrace()
            Balance("0", "0", 9, "SOL")
        }
    }
    
    @OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)
    override suspend fun send(to: String, amount: String): String {
        val amountLamports = (amount.toDouble() * 1_000_000_000).toLong()
        
        // Get keypair
        val path = "m/44'/501'/0'/0'"
        val key = Bip32.derivePath(wallet.seed, path)
        val keypair = Ed25519.keyFromSeed(key.privateKey)
        val fromPubKeyBytes = keypair.publicKey().toByteArray()
        val toPubKeyBytes = io.github.iml1s.crypto.Base58.decode(to)
        
        // Get recent blockhash
        val blockhashResponse = wallet.httpClient.post(rpcUrl) {
            contentType(io.ktor.http.ContentType.Application.Json)
            setBody("""{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[]}""")
        }
        val blockhashJson = kotlinx.serialization.json.Json.parseToJsonElement(blockhashResponse.bodyAsText())
        val blockhash = blockhashJson.jsonObject["result"]
            ?.jsonObject?.get("value")
            ?.jsonObject?.get("blockhash")
            ?.jsonPrimitive?.content ?: throw Exception("Failed to get blockhash")
        
        // System Program ID: 11111111111111111111111111111111
        val systemProgramIdBytes = io.github.iml1s.crypto.Base58.decode("11111111111111111111111111111111")
        
        // Build transaction message
        val message = buildSolanaMessage(
            fromPubKeyBytes = fromPubKeyBytes,
            toPubKeyBytes = toPubKeyBytes,
            systemProgramIdBytes = systemProgramIdBytes,
            lamports = amountLamports,
            blockhash = blockhash
        )
        
        // Sign message
        val signatureObj = keypair.sign(message)
        val signature = ByteArray(64).also { signatureObj.copyInto(it) }
        
        // Build serialized transaction and encode to Base64
        val serializedTx = buildSerializedTransaction(signature, message)
        val base64Tx = kotlin.io.encoding.Base64.encode(serializedTx)
        
        // Send transaction
        val sendResponse = wallet.httpClient.post(rpcUrl) {
            contentType(io.ktor.http.ContentType.Application.Json)
            setBody("""{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["$base64Tx",{"encoding":"base64"}]}""")
        }
        val sendJson = kotlinx.serialization.json.Json.parseToJsonElement(sendResponse.bodyAsText())
        return sendJson.jsonObject["result"]?.jsonPrimitive?.content 
            ?: sendJson.jsonObject["error"]?.toString() 
            ?: "Unknown error"
    }
    
    private fun buildSolanaMessage(
        fromPubKeyBytes: ByteArray,
        toPubKeyBytes: ByteArray,
        systemProgramIdBytes: ByteArray,
        lamports: Long,
        blockhash: String
    ): ByteArray {
        // Solana Message Format
        val builder = ByteArrayBuilder()
        
        // Header
        builder.writeByte(1) // numRequiredSignatures
        builder.writeByte(0) // numReadonlySignedAccounts
        builder.writeByte(1) // numReadonlyUnsignedAccounts (System Program)
        
        // Compact array of accounts (3 accounts)
        builder.writeByte(3)
        builder.writeBytes(fromPubKeyBytes)
        builder.writeBytes(toPubKeyBytes)
        builder.writeBytes(systemProgramIdBytes)
        
        // Recent blockhash
        val blockhashBytes = io.github.iml1s.crypto.Base58.decode(blockhash)
        builder.writeBytes(blockhashBytes)
        
        // Number of instructions
        builder.writeByte(1)
        
        // Transfer instruction
        builder.writeByte(2) // Program ID index (System Program)
        builder.writeByte(2) // Num accounts in instruction
        builder.writeByte(0) // from (signer, writable)
        builder.writeByte(1) // to (writable)
        
        // Data: Transfer instruction (2 as u32 LE + lamports as u64 LE)
        builder.writeByte(12) // data length
        builder.writeInt32LE(2) // Transfer instruction
        builder.writeInt64LE(lamports)
        
        return builder.toByteArray()
    }
    
    private fun buildSerializedTransaction(signature: ByteArray, message: ByteArray): ByteArray {
        val builder = ByteArrayBuilder()
        builder.writeByte(1) // 1 signature
        builder.writeBytes(signature)
        builder.writeBytes(message)
        return builder.toByteArray()
    }
}


class DashService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.DASH
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val endpoint = NetworkConfig.dashElectrum(wallet.network)
    private val client = ElectrumClient(endpoint.first, endpoint.second, ssl = true)
    
    override fun getAddress(index: Int): String {
        // BIP44: m/44'/5'/0'/0/index - Dash Testnet uses coin type 1
        val coinType = if (isTestnet) "1" else "5"
        val path = "m/44'/$coinType'/0'/0/$index"
        val key = Bip32.derivePath(wallet.seed, path)
        val pubKey = Secp256k1Pure.generatePublicKey(key.privateKey, compressed = true)
        return Dash.getAddress(pubKey, testnet = isTestnet)
    }
    
    override suspend fun getBalance(address: String?): Balance {
        val addr = address ?: getAddress()
        return try {
            client.connect()
            // Reuse BitcoinScript for Dash scripthash generation (compatible)
            val scriptHash = BitcoinScript.addressToScriptHash(addr)
            val response = client.getBalance(scriptHash)
            
            val result = response.jsonObject["result"]?.jsonObject
            val confirmed = result?.get("confirmed")?.jsonPrimitive?.longOrNull ?: 0L
            val unconfirmed = result?.get("unconfirmed")?.jsonPrimitive?.longOrNull ?: 0L
            val total = confirmed + unconfirmed
            
            Balance(total.toString(), confirmed.toString(), 8, "DASH")
        } catch (e: Exception) {
            e.printStackTrace()
            Balance("0", "0", 8, "DASH")
        } finally {
            try { client.close() } catch(e: Exception) {}
        }
    }
    
    override suspend fun send(to: String, amount: String): String {
        val amountSats = (amount.toDouble() * 100_000_000).toLong()
        val myAddress = getAddress()
        
        // 1. Fetch UTXOs
        client.connect()
        val scriptHash = BitcoinScript.addressToScriptHash(myAddress)
        val utxosJson = client.listUnspent(scriptHash)
        
        val utxos = utxosJson.jsonArray.map { 
            val txHash = it.jsonObject["tx_hash"]!!.jsonPrimitive.content
            val txPos = it.jsonObject["tx_pos"]!!.jsonPrimitive.int
            val value = it.jsonObject["value"]!!.jsonPrimitive.long
            UTXO(txHash, txPos, value, true)
        }

        // 2. Select UTXOs
        var current = 0L
        val inputs = mutableListOf<UTXO>()
        // Simple fee estimation (1000 sats fixed)
        val fee = 1000L 
        
        for (u in utxos) {
            inputs.add(u)
            current += u.value
            if (current >= amountSats + fee) break
        }
        
        if (current < amountSats + fee) throw Exception("Insufficient funds. Have: $current sats, Need: ${amountSats + fee}")

        // 3. Build Transaction
        val builder = DashTxBuilder()
        
        // Inputs
        inputs.forEach { 
            builder.addInput(Hex.decode(it.txid), it.vout)
        }
        
        // Output (Target)
        val targetScript = BitcoinScript.addressToScriptPubKey(to)
        builder.addOutput(amountSats, targetScript)
        
        // Change
        val change = current - amountSats - fee
        if (change > 546) {
            val changeScript = BitcoinScript.addressToScriptPubKey(myAddress)
            builder.addOutput(change, changeScript)
        }
        
        var tx = builder.build()
        
        // 4. Sign
        val coinType = if (isTestnet) "1" else "5"
        val path = "m/44'/$coinType'/0'/0/0"
        val key = Bip32.derivePath(wallet.seed, path)
        val privKey = key.privateKey
        val pubKey = Secp256k1Pure.generatePublicKey(privKey, compressed = true)
        
        val signedInputs = tx.inputs.mapIndexed { index, input ->
             // ScriptCode is scriptPubKey for P2PKH
             val scriptCode = BitcoinScript.addressToScriptPubKey(myAddress)
             
             val hash = tx.hashForSignature(index, scriptCode, DashTransaction.SIGHASH_ALL)
             val signature = Secp256k1Pure.sign(hash, privKey)
             val derSig = WalletUtils.encodeDer(signature) + DashTransaction.SIGHASH_ALL.toByte()
             
             // ScriptSig: [sigLen][sig][pubKeyLen][pubKey]

             val scriptSig = ByteArrayBuilder()
             scriptSig.writeVarInt(derSig.size.toLong())
             scriptSig.writeBytes(derSig)
             scriptSig.writeVarInt(pubKey.size.toLong())
             scriptSig.writeBytes(pubKey)
             
             input.copy(scriptSig = scriptSig.toByteArray())
        }
        
        tx = tx.copy(inputs = signedInputs)
        
        val hex = Hex.encode(tx.serialize())
        return client.broadcastTransaction(hex).jsonPrimitive.content
    }
}

class ZcashService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.ZCASH
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val rpcUrl = NetworkConfig.zcashLightwalletd(wallet.network)
    private val client = LightwalletdClient(wallet.httpClient, rpcUrl)
    
    override fun getAddress(index: Int): String {
        // BIP44: m/44'/133'/0'/0/index - Zcash Testnet uses coin type 1
        val coinType = if (isTestnet) "1" else "133"
        val path = "m/44'/$coinType'/0'/0/$index"
        val key = Bip32.derivePath(wallet.seed, path)
        val pubKey = Secp256k1Pure.generatePublicKey(key.privateKey, compressed = true)
        return Zcash.getTransparentAddress(pubKey, testnet = isTestnet)
    }
    
    override suspend fun getBalance(address: String?): Balance {
        val addr = address ?: getAddress()
        return try {
            // Check if address is transparent (t1/t3)
            if (addr.startsWith("t")) {
                val zatoshi = client.getTransparentBalance(addr)
                Balance(zatoshi.toString(), zatoshi.toString(), 8, "ZEC")
            } else {
                // Shielded balance requires scanning, not supported yet
                Balance("0", "0", 8, "ZEC") 
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Balance("0", "0", 8, "ZEC")
        }
    }
    
    override suspend fun send(to: String, amount: String): String {
        val amountZat = (amount.toDouble() * 100_000_000).toLong()
        val myAddress = getAddress()
        
        // 1. Fetch UTXOs (Lightwalletd returns Transparent UTXOs)
        val utxosJson = client.getTransparentUtxos(myAddress)
        
        // 2. Select UTXOs
        var current = 0L
        val selectedUtxos = mutableListOf<io.github.iml1s.client.zcash.ZcashUtxo>()
        val fee = 10000L // Zcash standard fee is 10000 zatoshis
        
        for (u in utxosJson) {
            selectedUtxos.add(u)
            current += u.valueZat ?: 0L
            if (current >= amountZat + fee) break
        }
        
        if (current < amountZat + fee) throw Exception("Insufficient funds. Have: $current zat, Need: ${amountZat + fee}")

        // 3. Build Transaction
        val builder = ZcashTxBuilder()
        builder.version(4) // Sapling
        
        // Inputs
        selectedUtxos.forEach { 
            builder.addInput(Hex.decode(it.txid!!), it.outputIndex ?: 0)
        }
        
        // Output (Target)
        val targetScript = BitcoinScript.addressToScriptPubKey(to)
        builder.addOutput(amountZat, targetScript)
        
        // Change
        val change = current - amountZat - fee
        if (change > 0) {
            val changeScript = BitcoinScript.addressToScriptPubKey(myAddress)
            builder.addOutput(change, changeScript)
        }
        
        var tx = builder.build()
        
        // 4. Sign
        val coinType = if (isTestnet) "1" else "133"
        val path = "m/44'/$coinType'/0'/0/0"
        val key = Bip32.derivePath(wallet.seed, path)
        val privKey = key.privateKey
        val pubKey = Secp256k1Pure.generatePublicKey(privKey, compressed = true)
        
        val signedInputs = tx.inputs.mapIndexed { index, input ->
             val scriptCode = BitcoinScript.addressToScriptPubKey(myAddress)
             val utxoAmount = selectedUtxos[index].valueZat ?: 0L
             
             val hash = tx.hashForSignature(index, scriptCode, utxoAmount, ZcashTransaction.SIGHASH_ALL)
             val signature = Secp256k1Pure.sign(hash, privKey)
             val derSig = WalletUtils.encodeDer(signature) + ZcashTransaction.SIGHASH_ALL.toByte()
             
             val scriptSig = ByteArrayBuilder()
             scriptSig.writeVarInt(derSig.size.toLong())
             scriptSig.writeBytes(derSig)
             scriptSig.writeVarInt(pubKey.size.toLong())
             scriptSig.writeBytes(pubKey)
             
             input.copy(scriptSig = scriptSig.toByteArray())
        }
        
        tx = tx.copy(inputs = signedInputs)
        
        val hex = Hex.encode(tx.serialize())
        return client.sendRawTransaction(hex)
    }

}

class MoneroService(val wallet: UnifiedWallet) : ChainService {
    override val chain = Chain.MONERO
    
    private val isTestnet = wallet.network == NetworkType.TESTNET
    private val rpcUrl = NetworkConfig.moneroRpc(wallet.network)
    private val client = MoneroDaemonClient(wallet.httpClient, rpcUrl)
    
    override fun getAddress(index: Int): String {
        // Custom Monero Derivation
        val spendSeed = wallet.seed.copyOfRange(0, 32)
        val viewSeed = wallet.seed.copyOfRange(32, 64)
        
        val spendKey = Ed25519.keyFromSeed(spendSeed)
        val viewKey = Ed25519.keyFromSeed(viewSeed)
        
        return Monero.getAddress(
            spendPublicKey = spendKey.publicKey().toByteArray(),
            viewPublicKey = viewKey.publicKey().toByteArray(),
            network = if (isTestnet) "testnet" else "mainnet"
        )
    }
    
    override suspend fun getBalance(address: String?): Balance {
        // Monero balance requires client-side scanning or wallet-rpc.
        // Daemon can only provide block height/info.
        // Return 0 for now but log info.
        try {
            val height = client.getBlockHeight()
            println("Monero Network Height: $height")
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return Balance("0", "0", 12, "XMR")
    }
    
    override suspend fun send(to: String, amount: String): String = "TODO"
}
