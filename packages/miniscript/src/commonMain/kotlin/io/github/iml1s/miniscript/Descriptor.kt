package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.context.BareCtx
import io.github.iml1s.miniscript.context.Segwitv0
import io.github.iml1s.miniscript.context.Tap
import io.github.iml1s.miniscript.node.ScriptElt
import io.github.iml1s.miniscript.node.Terminal
import io.github.iml1s.crypto.Digests
import io.github.iml1s.crypto.Ripemd160
import io.github.iml1s.address.Bech32
import io.github.iml1s.address.Base58

/**
 * Represents a Bitcoin Output Descriptor as defined in BIPs 380-386.
 */
sealed class Descriptor<Pk : MiniscriptKey> {

    /**
     * Generate the scriptPubKey for this descriptor.
     */
    abstract fun scriptPubKey(): List<ScriptElt>

    /**
     * Generate the witness script for this descriptor (if applicable).
     */
    open fun witnessScript(): List<ScriptElt>? = null

    /**
     * Compute the hash for P2SH (RedeemScript hash).
     */
    protected fun hash160(data: ByteArray): ByteArray {
        val sha256 = sha256(data)
        return Ripemd160.hash(sha256)
    }

    /**
     * Compute the hash for P2WSH (WitnessScript sha256).
     */
    protected fun sha256(data: ByteArray): ByteArray {
        val digest = Digests.sha256()
        val result = ByteArray(digest.getDigestSize())
        digest.update(data, 0, data.size)
        digest.doFinal(result, 0)
        return result
    }

    /**
     * Compute the checksum for this descriptor (BIP 380).
     */
    fun checksum(): String {
        return computeChecksum(toString().split('#')[0])
    }

    /** pkh(KEY) */
    data class Pkh<Pk : MiniscriptKey>(val key: Pk) : Descriptor<Pk>() {
        override fun toString(): String = "pkh($key)"
        override fun scriptPubKey(): List<ScriptElt> {
            val hash = if (key is ToPublicKey) key.toHash160(byteArrayOf()) else key.toString().encodeToByteArray()
            return listOf(
                ScriptElt.OP_DUP,
                ScriptElt.OP_HASH160,
                ScriptElt.Push(hash),
                ScriptElt.OP_EQUALVERIFY,
                ScriptElt.OP_CHECKSIG
            )
        }
    }

    /** pk(KEY) - P2PK */
    data class Pk<Pk : MiniscriptKey>(val key: Pk) : Descriptor<Pk>() {
        override fun toString(): String = "pk($key)"
        override fun scriptPubKey(): List<ScriptElt> {
            val pubkey = if (key is ToPublicKey) key.toPublicKey() else key.toString().encodeToByteArray()
            return listOf(
                ScriptElt.Push(pubkey),
                ScriptElt.OP_CHECKSIG
            )
        }
    }

    /** multi(k, pubkey1, pubkey2, ...) */
    data class Multi<Pk : MiniscriptKey>(val threshold: Int, val keys: List<Pk>) : Descriptor<Pk>() {
        override fun toString(): String = "multi($threshold,${keys.joinToString(",")})"
        override fun scriptPubKey(): List<ScriptElt> {
            val elts = mutableListOf<ScriptElt>()
            elts.add(ScriptElt.fromInt(threshold))
            for (key in keys) {
                val pubkey = if (key is ToPublicKey) key.toPublicKey() else key.toString().encodeToByteArray()
                elts.add(ScriptElt.Push(pubkey))
            }
            elts.add(ScriptElt.fromInt(keys.size))
            elts.add(ScriptElt.OP_CHECKMULTISIG)
            return elts
        }
    }

    /** sortedmulti(k, pubkey1, pubkey2, ...) */
    data class SortedMulti<Pk : MiniscriptKey>(val threshold: Int, val keys: List<Pk>) : Descriptor<Pk>() {
        override fun toString(): String = "sortedmulti($threshold,${keys.joinToString(",")})"
        override fun scriptPubKey(): List<ScriptElt> {
            val sortedKeys = keys.sortedBy { 
                val pk = if (it is ToPublicKey) it.toPublicKey() else it.toString().encodeToByteArray()
                io.github.iml1s.crypto.Hex.encode(pk)
            }
            return Multi(threshold, sortedKeys).scriptPubKey()
        }
    }

    /** wpkh(KEY) */
    data class Wpkh<Pk : MiniscriptKey>(val key: Pk) : Descriptor<Pk>() {
        override fun toString(): String = "wpkh($key)"
        override fun scriptPubKey(): List<ScriptElt> {
            val hash = if (key is ToPublicKey) key.toHash160(byteArrayOf()) else key.toString().encodeToByteArray()
            return listOf(
                ScriptElt.OP_0,
                ScriptElt.Push(hash)
            )
        }
    }

    /** sh(Descriptor) */
    data class Sh<Pk : MiniscriptKey>(val sub: Descriptor<Pk>) : Descriptor<Pk>() {
        override fun toString(): String = "sh($sub)"
        override fun scriptPubKey(): List<ScriptElt> {
            val redeemScriptBytes = when (sub) {
                is Wpkh -> scriptToBytes(sub.scriptPubKey())
                is Wsh -> scriptToBytes(sub.scriptPubKey())
                else -> scriptToBytes(sub.scriptPubKey()) // Legacy P2SH
            }
            return listOf(
                ScriptElt.OP_HASH160,
                ScriptElt.Push(hash160(redeemScriptBytes)),
                ScriptElt.OP_EQUAL
            )
        }
    }

    /** wsh(Miniscript) */
    data class Wsh<Pk : MiniscriptKey>(val miniscript: Miniscript<Pk, Segwitv0>) : Descriptor<Pk>() {
        override fun toString(): String = "wsh($miniscript)"
        override fun scriptPubKey(): List<ScriptElt> {
            val witnessScriptBytes = scriptToBytes(miniscript.toScript())
            return listOf(
                ScriptElt.OP_0,
                ScriptElt.Push(sha256(witnessScriptBytes))
            )
        }

        override fun witnessScript(): List<ScriptElt> = miniscript.toScript()
    }

    /** tr(KEY) or tr(KEY, {TREE}) */
    // Placeholder for Taproot until we have full BIP-341/342 support in the library
    data class Tr<Pk : MiniscriptKey>(val internalKey: Pk, val tree: TapTree? = null) : Descriptor<Pk>() {
        override fun toString(): String = if (tree == null) "tr($internalKey)" else "tr($internalKey,$tree)"
        override fun scriptPubKey(): List<ScriptElt> {
            val internalKeyBytes = if (internalKey is ToPublicKey) internalKey.toPublicKey() else internalKey.toString().encodeToByteArray()
            // Ensure 32 bytes (x-only)
            val xOnly = if (internalKeyBytes.size == 33) internalKeyBytes.copyOfRange(1, 33) else internalKeyBytes
            
            val outputKey = if (tree == null) {
                 tweak(xOnly, null)
            } else {
                 tweak(xOnly, tree.rootHash())
            }
            
            return listOf(
                ScriptElt.OP_1,
                ScriptElt.Push(outputKey)
            )
        }
        
        private fun tweak(pubKey: ByteArray, merkleRoot: ByteArray?): ByteArray {
             // pubKey is x-only (32 bytes). Secp256k1Pure expects 33 bytes for tweaking (compressed).
             // BIP-341: P has implicit even Y.
             val pubKey33 = ByteArray(33)
             pubKey33[0] = 0x02
             System.arraycopy(pubKey, 0, pubKey33, 1, 32)
             
             val tweak = if (merkleRoot == null) {
                 TapTree.taggedHash("TapTweak", pubKey)
             } else {
                 // tagged_hash("TapTweak", pubKey || merkle_root)
                 val data = ByteArray(pubKey.size + merkleRoot.size)
                 System.arraycopy(pubKey, 0, data, 0, pubKey.size)
                 System.arraycopy(merkleRoot, 0, data, pubKey.size, merkleRoot.size)
                 TapTree.taggedHash("TapTweak", data)
             }
             
             // Q = P + H(P|c)G
             val tweaked33 = io.github.iml1s.crypto.Secp256k1Pure.pubKeyTweakAdd(pubKey33, tweak)
             
             // Return x-only (slice 1..33)
             return tweaked33.copyOfRange(1, 33)
        }
    }
    
    /** addr(ADDRESS) */
    data class Addr<Pk : MiniscriptKey>(val address: String) : Descriptor<Pk>() {
        override fun toString(): String = "addr($address)"
        override fun scriptPubKey(): List<ScriptElt> {
            // Try Bech32 (SegWit / Taproot)
            val decodedBech32 = Bech32.decode(address)
            if (decodedBech32 != null) {
               val version = decodedBech32.data[0].toInt()
               
               // Drop version byte and convert 5-bit to 8-bit
               val payload5bit = decodedBech32.data.sliceArray(1 until decodedBech32.data.size)
               val data = Bech32.convertBits(payload5bit, 5, 8, false)
               
               if (data != null) {
                   return if (version == 0) {
                        // P2WPKH (20 bytes) or P2WSH (32 bytes)
                        listOf(ScriptElt.OP_0, ScriptElt.Push(data))
                   } else if (version == 1 && data.size == 32) {
                        // P2TR
                        listOf(ScriptElt.OP_1, ScriptElt.Push(data))
                   } else {
                        // Unknown witness version
                        throw IllegalArgumentException("Unsupported witness version/length")
                   }
               }
            }
            
            // Not Bech32, try Base58
            try {
                val decodedPair = Base58.decodeCheck(address) ?: throw IllegalArgumentException("Invalid address checksum")
                val version = decodedPair.first.toInt() and 0xFF
                val payload = decodedPair.second
                
                if (payload.size != 20) throw IllegalArgumentException("Invalid Base58 payload length: ${payload.size}")
                
                return when (version) {
                    0x00, 0x6f -> { // P2PKH (Mainnet / Testnet)
                         listOf(
                             ScriptElt.OP_DUP,
                             ScriptElt.OP_HASH160,
                             ScriptElt.Push(payload),
                             ScriptElt.OP_EQUALVERIFY,
                             ScriptElt.OP_CHECKSIG
                         )
                    }
                    0x05, 0xc4 -> { // P2SH (Mainnet / Testnet)
                         listOf(
                             ScriptElt.OP_HASH160,
                             ScriptElt.Push(payload),
                             ScriptElt.OP_EQUAL
                         )
                    }
                    else -> throw IllegalArgumentException("Unknown Base58 address version: $version")
                }
            } catch (e2: Exception) {
                throw IllegalArgumentException("Invalid address format or unsupported type: ${e2.message}")
            }
        }
    }

    /** raw(HEX) */
    data class Raw<Pk : MiniscriptKey>(val hex: String) : Descriptor<Pk>() {
        override fun toString(): String = "raw($hex)"
        override fun scriptPubKey(): List<ScriptElt> {
            val bytes = io.github.iml1s.crypto.Hex.decode(hex)
            return listOf(ScriptElt.RawBytes(bytes))
        }
    }

    companion object {
        private const val CHARSET = "023456789acdefghjklmnpqrstuvwxyz"

        fun computeChecksum(s: String): String {
            val polyMod = polyMod(s)
            val checksum = StringBuilder()
            for (i in 0 until 8) {
                val index = (polyMod shr (5 * (7 - i))) and 31
                checksum.append(CHARSET[index.toInt()])
            }
            return checksum.toString()
        }

        private fun polyMod(s: String): Long {
            var c = 1L
            for (ch in s) {
                val valCh = CHARSET.indexOf(ch)
                val chCode = if (valCh != -1) valCh.toLong() else ch.code.toLong()
                
                val b = c shr 35
                c = ((c and 0x07ffffffffL) shl 5) xor chCode
                
                if (b and 1 != 0L) c = c xor 0xf5dee51989L
                if (b and 2 != 0L) c = c xor 0xa9fdca3312L
                if (b and 4 != 0L) c = c xor 0x1ba1050260L
                if (b and 8 != 0L) c = c xor 0x2ef82d3c7dL
                if (b and 16 != 0L) c = c xor 0x436997034dL
            }
            return c
        }
        
        /**
         * Helper to convert script elements to bytes.
         */
        internal fun scriptToBytes(elts: List<ScriptElt>): ByteArray {
            val out = mutableListOf<Byte>()
            for (elt in elts) {
                when (elt) {
                    is ScriptElt.Op -> out.add(elt.code.toByte())
                    is ScriptElt.Push -> {
                        val data = elt.data
                        val len = data.size
                        when {
                            len == 0 -> out.add(0x00.toByte())
                            len <= 75 -> {
                                out.add(len.toByte())
                                out.addAll(data.toList())
                            }
                            len <= 255 -> {
                                out.add(0x4c.toByte())
                                out.add(len.toByte())
                                out.addAll(data.toList())
                            }
                            len <= 65535 -> {
                                out.add(0x4d.toByte())
                                out.add((len and 0xff).toByte())
                                out.add(((len shr 8) and 0xff).toByte())
                                out.addAll(data.toList())
                            }
                            else -> {
                                out.add(0x4e.toByte())
                                out.add((len and 0xff).toByte())
                                out.add(((len shr 8) and 0xff).toByte())
                                out.add(((len shr 16) and 0xff).toByte())
                                out.add(((len shr 24) and 0xff).toByte())
                                out.addAll(data.toList())
                            }
                        }
                    }
                    is ScriptElt.RawBytes -> out.addAll(elt.bytes.toList())
                }
            }
            return out.toByteArray()
        }
    }
}
