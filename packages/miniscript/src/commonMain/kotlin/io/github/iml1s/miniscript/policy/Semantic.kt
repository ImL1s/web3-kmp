package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.AbsLockTime
import io.github.iml1s.miniscript.MiniscriptKey
import io.github.iml1s.miniscript.RelLockTime
import io.github.iml1s.miniscript.Threshold
import kotlin.math.max

/**
 * Abstract policy which corresponds to the semantics of a miniscript and
 * which allows complex forms of analysis, e.g. filtering and normalization.
 */
sealed class Semantic<out Pk : MiniscriptKey> {
    object Unsatisfiable : Semantic<Nothing>() {
        override fun toString() = "UNSATISFIABLE"
    }
    object Trivial : Semantic<Nothing>() {
        override fun toString() = "TRIVIAL"
    }
    data class Key<out Pk : MiniscriptKey>(val key: Pk) : Semantic<Pk>() {
        override fun toString() = "pk($key)"
    }
    data class After(val lockTime: AbsLockTime) : Semantic<Nothing>() {
        override fun toString() = "after(${lockTime.value})"
    }
    data class Older(val lockTime: RelLockTime) : Semantic<Nothing>() {
        override fun toString() = "older(${lockTime.value})"
    }
    data class Sha256(val hash: ByteArray) : Semantic<Nothing>() {
        override fun toString() = "sha256(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Sha256) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Hash256(val hash: ByteArray) : Semantic<Nothing>() {
        override fun toString() = "hash256(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Hash256) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Ripemd160(val hash: ByteArray) : Semantic<Nothing>() {
        override fun toString() = "ripemd160(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Ripemd160) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Hash160(val hash: ByteArray) : Semantic<Nothing>() {
        override fun toString() = "hash160(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Hash160) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Thresh<out Pk : MiniscriptKey>(val threshold: Threshold<Semantic<Pk>>) : Semantic<Pk>() {
        override fun toString(): String {
            return if (threshold.k == threshold.data.size) {
                "and(${threshold.data.joinToString(",")})"
            } else if (threshold.k == 1) {
                "or(${threshold.data.joinToString(",")})"
            } else {
                "thresh(${threshold.k},${threshold.data.joinToString(",")})"
            }
        }
    }

    /**
     * Flattens out trees of `And`s and `Or`s; eliminate `Trivial` and
     * `Unsatisfiable`s. Does not reorder any branches.
     */
    fun normalized(): Semantic<Pk> {
        return when (this) {
            is Thresh -> {
                val subs = threshold.data.map { it.normalized() }
                val trivialCount = subs.count { it is Trivial }
                val unsatisfiableCount = subs.count { it is Unsatisfiable }
                
                val n = subs.size - unsatisfiableCount - trivialCount
                val m = max(0, threshold.k - trivialCount)

                val isAnd = m == n
                val isOr = m == 1

                val retSubs = mutableListOf<Semantic<Pk>>()
                for (sub in subs) {
                    when (sub) {
                        is Trivial, is Unsatisfiable -> {} // Skip
                        is Thresh -> {
                            when {
                                isAnd && isOr -> { // m = n = 1
                                    retSubs.add(sub)
                                }
                                isAnd && sub.threshold.k == sub.threshold.data.size -> { // AND inside AND
                                    retSubs.addAll(sub.threshold.data)
                                }
                                isOr && sub.threshold.k == 1 -> { // OR inside OR
                                    retSubs.addAll(sub.threshold.data)
                                }
                                else -> retSubs.add(sub)
                            }
                        }
                        else -> retSubs.add(sub)
                    }
                }

                if (m == 0) return Trivial
                if (m > retSubs.size) return Unsatisfiable
                if (retSubs.size == 1) return retSubs.first()
                
                if (isAnd) return Thresh(Threshold(retSubs.size, retSubs))
                if (isOr) return Thresh(Threshold(1, retSubs))
                return Thresh(Threshold(m, retSubs))
            }
            else -> this
        }
    }

    companion object {
        fun <Pk : MiniscriptKey> fromStr(s: String, keyParser: (String) -> Pk): Semantic<Pk> {
            val tree = io.github.iml1s.miniscript.parser.MiniscriptParser.parse(s)
            return fromTree(tree, keyParser)
        }

        private fun <Pk : MiniscriptKey> fromTree(
            tree: io.github.iml1s.miniscript.parser.TokenTree,
            keyParser: (String) -> Pk
        ): Semantic<Pk> {
            return when (tree.name) {
                "UNSATISFIABLE" -> {
                    checkChildren(tree, 0)
                    Unsatisfiable
                }
                "TRIVIAL" -> {
                    checkChildren(tree, 0)
                    Trivial
                }
                "pk" -> {
                    checkChildren(tree, 1)
                    val keyStr = tree.children[0].name
                    Key(keyParser(keyStr))
                }
                "after" -> {
                    checkChildren(tree, 1)
                    val time = tree.children[0].name.toUIntOrNull()
                        ?: throw IllegalArgumentException("Invalid after time")
                    After(AbsLockTime(time))
                }
                "older" -> {
                    checkChildren(tree, 1)
                    val time = tree.children[0].name.toUIntOrNull()
                        ?: throw IllegalArgumentException("Invalid older time")
                    Older(RelLockTime(time))
                }
                "sha256" -> {
                    checkChildren(tree, 1)
                    // FIXME hash parsing generic
                    throw IllegalArgumentException("sha256 parsing not implemented")
                }
                "and" -> {
                    if (tree.children.size < 2) throw IllegalArgumentException("and requires at least 2 children")
                    val subs = tree.children.map { fromTree(it, keyParser) }
                    Thresh(Threshold(subs.size, subs))
                }
                "or" -> {
                    if (tree.children.size < 2) throw IllegalArgumentException("or requires at least 2 children")
                    val subs = tree.children.map { fromTree(it, keyParser) }
                    Thresh(Threshold(1, subs))
                }
                "thresh" -> {
                    if (tree.children.isEmpty()) throw IllegalArgumentException("thresh requires k")
                    val k = tree.children[0].name.toIntOrNull()
                        ?: throw IllegalArgumentException("Invalid k for thresh")
                    val subs = tree.children.drop(1).map { fromTree(it, keyParser) }
                    Thresh(Threshold(k, subs))
                }
                else -> throw IllegalArgumentException("Unknown policy fragment: ${tree.name}")
            }
        }

        private fun checkChildren(tree: io.github.iml1s.miniscript.parser.TokenTree, count: Int) {
            if (tree.children.size != count) {
                throw IllegalArgumentException("${tree.name} requires $count children, got ${tree.children.size}")
            }
        }
    }
}
