package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.node.ScriptElt
import io.github.iml1s.crypto.Digests

/**
 * Represents a Taproot Script Tree.
 */
sealed class TapTree {
    abstract fun rootHash(): ByteArray

    /**
     * A leaf in the script tree.
     */
    data class Leaf(val script: List<ScriptElt>, val version: Int = 0xC0) : TapTree() {
        override fun rootHash(): ByteArray {
            val scriptBytes = Descriptor.scriptToBytes(script)
            val leafVersion = version.toByte()
            val buffer = ByteArray(1 + scriptBytes.size) // version (1) + script_len (compact? no, just script)
            // BIP-341: HashTapLeaf(version || compact_size(script) || script)
            // But wait, standard says: HashTapLeaf(leaf_version || ser_script(script))
            // ser_script(s) = compact_size(len(s)) || s.
            
            // Let's implement serialization helper or do it manually.
            val scriptSize = encodeVarInt(scriptBytes.size.toLong())
            val data = ByteArray(1 + scriptSize.size + scriptBytes.size)
            data[0] = leafVersion
            System.arraycopy(scriptSize, 0, data, 1, scriptSize.size)
            System.arraycopy(scriptBytes, 0, data, 1 + scriptSize.size, scriptBytes.size)
            
            return taggedHash("TapLeaf", data)
        }
    }

    /**
     * A branching node in the script tree.
     */
    data class Branch(val left: TapTree, val right: TapTree) : TapTree() {
        override fun rootHash(): ByteArray {
            val h1 = left.rootHash()
            val h2 = right.rootHash()
            // Lexicographical sort
            val (min, max) = if (compare(h1, h2) < 0) h1 to h2 else h2 to h1
            return taggedHash("TapBranch", min + max)
        }
    }

    companion object {
        private fun compare(a: ByteArray, b: ByteArray): Int {
            for (i in a.indices) {
                val b1 = a[i].toInt() and 0xff
                val b2 = b[i].toInt() and 0xff
                if (b1 != b2) return b1 - b2
            }
            return 0
        }

        public fun taggedHash(tag: String, data: ByteArray): ByteArray {
            val tagHash = sha256(tag.encodeToByteArray())
            val digest = Digests.sha256()
            val result = ByteArray(32)
            digest.update(tagHash, 0, tagHash.size)
            digest.update(tagHash, 0, tagHash.size)
            digest.update(data, 0, data.size)
            digest.doFinal(result, 0)
            return result
        }

        private fun sha256(data: ByteArray): ByteArray {
            val digest = Digests.sha256()
            val result = ByteArray(32)
            digest.update(data, 0, data.size)
            digest.doFinal(result, 0)
            return result
        }

        private fun encodeVarInt(v: Long): ByteArray {
            return when {
                v < 0xfd -> byteArrayOf(v.toByte())
                v <= 0xffff -> {
                    val b = ByteArray(3)
                    b[0] = 0xfd.toByte()
                    b[1] = (v and 0xff).toByte()
                    b[2] = ((v shr 8) and 0xff).toByte()
                    b
                }
                v <= 0xffffffffL -> {
                    val b = ByteArray(5)
                    b[0] = 0xfe.toByte()
                    b[1] = (v and 0xff).toByte()
                    b[2] = ((v shr 8) and 0xff).toByte()
                    b[3] = ((v shr 16) and 0xff).toByte()
                    b[4] = ((v shr 24) and 0xff).toByte()
                    b
                }
                else -> {
                    val b = ByteArray(9)
                    b[0] = 0xff.toByte()
                    b[1] = (v and 0xff).toByte()
                    b[2] = ((v shr 8) and 0xff).toByte()
                    b[3] = ((v shr 16) and 0xff).toByte()
                    b[4] = ((v shr 24) and 0xff).toByte()
                    b[5] = ((v shr 32) and 0xff).toByte()
                    b[6] = ((v shr 40) and 0xff).toByte()
                    b[7] = ((v shr 48) and 0xff).toByte()
                    b[8] = ((v shr 56) and 0xff).toByte()
                    b
                }
            }
        }
    }
}
