package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.AbsLockTime
import io.github.iml1s.miniscript.MiniscriptKey
import io.github.iml1s.miniscript.RelLockTime
import io.github.iml1s.miniscript.Threshold

/**
 * Concrete policy which corresponds directly to a miniscript structure,
 * and whose disjunctions are annotated with satisfaction probabilities
 * to assist the compiler.
 */
sealed class Concrete<out Pk : MiniscriptKey> {
    object Unsatisfiable : Concrete<Nothing>() {
        override fun toString() = "UNSATISFIABLE"
    }
    object Trivial : Concrete<Nothing>() {
        override fun toString() = "TRIVIAL"
    }
    data class Key<out Pk : MiniscriptKey>(val key: Pk) : Concrete<Pk>() {
        override fun toString() = "pk($key)"
    }
    data class After(val lockTime: AbsLockTime) : Concrete<Nothing>() {
        override fun toString() = "after(${lockTime.value})"
    }
    data class Older(val lockTime: RelLockTime) : Concrete<Nothing>() {
        override fun toString() = "older(${lockTime.value})"
    }
    data class Sha256(val hash: ByteArray) : Concrete<Nothing>() {
        override fun toString() = "sha256(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Sha256) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Hash256(val hash: ByteArray) : Concrete<Nothing>() {
        override fun toString() = "hash256(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Hash256) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Ripemd160(val hash: ByteArray) : Concrete<Nothing>() {
        override fun toString() = "ripemd160(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Ripemd160) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class Hash160(val hash: ByteArray) : Concrete<Nothing>() {
        override fun toString() = "hash160(${io.github.iml1s.crypto.Hex.encode(hash)})"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Hash160) return false
            return hash.contentEquals(other.hash)
        }
        override fun hashCode(): Int = hash.contentHashCode()
    }
    data class And<out Pk : MiniscriptKey>(val subs: List<Concrete<Pk>>) : Concrete<Pk>() {
        override fun toString() = "and(${subs.joinToString(",")})"
    }
    data class Or<out Pk : MiniscriptKey>(val subs: List<Pair<UInt, Concrete<Pk>>>) : Concrete<Pk>() {
        override fun toString() = "or(${subs.joinToString(",") { "${it.first}@${it.second}" }})"
    }
    data class Thresh<out Pk : MiniscriptKey>(val threshold: Threshold<Concrete<Pk>>) : Concrete<Pk>() {
        override fun toString() = "thresh(${threshold.k},${threshold.data.joinToString(",")})"
    }

    fun lift(): Semantic<Pk> {
        val ret = when (this) {
            Unsatisfiable -> Semantic.Unsatisfiable
            Trivial -> Semantic.Trivial
            is Key -> Semantic.Key(key)
            is After -> Semantic.After(lockTime)
            is Older -> Semantic.Older(lockTime)
            is Sha256 -> Semantic.Sha256(hash)
            is Hash256 -> Semantic.Hash256(hash)
            is Ripemd160 -> Semantic.Ripemd160(hash)
            is Hash160 -> Semantic.Hash160(hash)
            is And -> {
                val semanticSubs = subs.map { it.lift() }
                Semantic.Thresh(Threshold(semanticSubs.size, semanticSubs))
            }
            is Or -> {
                val semanticSubs = subs.map { it.second.lift() }
                Semantic.Thresh(Threshold(1, semanticSubs))
            }
            is Thresh -> {
                val semanticSubs = threshold.data.map { it.lift() }
                Semantic.Thresh(Threshold(threshold.k, semanticSubs))
            }
        }
        return ret.normalized()
    }

    companion object {
        fun <Pk : MiniscriptKey> fromStr(s: String, keyParser: (String) -> Pk): Concrete<Pk> {
            val tree = io.github.iml1s.miniscript.parser.MiniscriptParser.parse(s)
            return fromTree(tree, keyParser)
        }

        private fun <Pk : MiniscriptKey> fromTree(
            tree: io.github.iml1s.miniscript.parser.TokenTree,
            keyParser: (String) -> Pk
        ): Concrete<Pk> {
            val (prob, name) = parseProbName(tree.name)
            // If this node had a probability attached (e.g., 99@pk), 
            // the probability is essentially stripped here during general parsing.
            // But usually 'Or' children handle probabilities explicitly.
            // When parsing recursively, we don't return probability unless caller expects it.
        
            return when (name) {
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
                    throw IllegalArgumentException("sha256 parsing not implemented")
                }
                "and" -> {
                    // And children generally don't have probabilities in standard Miniscript policy?
                    // Rust implementation: And(Vec<Arc<Policy<Pk>>>)
                    val subs = tree.children.map { fromTree(it, keyParser) }
                    And(subs)
                }
                "or" -> {
                    // Or children might have probabilities: 99@pk(A)
                    val subs = tree.children.map { child ->
                        val (p, childName) = parseProbName(child.name)
                        // Adjust child name for recursion
                        val cleanChild = io.github.iml1s.miniscript.parser.TokenTree(childName, child.children)
                        val subPolicy = fromTree(cleanChild, keyParser)
                        (p ?: 1u) to subPolicy
                    }
                    Or(subs)
                }
                "thresh" -> {
                    if (tree.children.isEmpty()) throw IllegalArgumentException("thresh requires k")
                    val k = tree.children[0].name.toIntOrNull()
                        ?: throw IllegalArgumentException("Invalid k for thresh")
                    val subs = tree.children.drop(1).map { fromTree(it, keyParser) }
                    Thresh(Threshold(k, subs))
                }
                else -> throw IllegalArgumentException("Unknown concrete policy fragment: $name")
            }
        }

        private fun parseProbName(s: String): Pair<UInt?, String> {
            val parts = s.split('@')
            return if (parts.size == 2) {
                val prob = parts[0].toUIntOrNull()
                val name = parts[1]
                prob to name
            } else {
                null to s
            }
        }

        private fun checkChildren(tree: io.github.iml1s.miniscript.parser.TokenTree, count: Int) {
            if (tree.children.size != count) {
                throw IllegalArgumentException("${tree.name} requires $count children, got ${tree.children.size}")
            }
        }
    }
}
