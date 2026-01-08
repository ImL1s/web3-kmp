package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.context.ScriptContext
import io.github.iml1s.miniscript.node.Terminal
import io.github.iml1s.miniscript.node.Terminal.False
import io.github.iml1s.miniscript.node.Terminal.True
import io.github.iml1s.miniscript.node.Terminal.PkK
import io.github.iml1s.miniscript.node.Terminal.PkH
import io.github.iml1s.miniscript.node.Terminal.RawPkH
import io.github.iml1s.miniscript.node.Terminal.After
import io.github.iml1s.miniscript.node.Terminal.Older
import io.github.iml1s.miniscript.node.Terminal.Sha256
import io.github.iml1s.miniscript.node.Terminal.Hash256
import io.github.iml1s.miniscript.node.Terminal.Ripemd160
import io.github.iml1s.miniscript.node.Terminal.Hash160
import io.github.iml1s.miniscript.node.Terminal.AndV
import io.github.iml1s.miniscript.node.Terminal.AndB
import io.github.iml1s.miniscript.node.Terminal.AndOr
import io.github.iml1s.miniscript.node.Terminal.OrB
import io.github.iml1s.miniscript.node.Terminal.OrD
import io.github.iml1s.miniscript.node.Terminal.OrC
import io.github.iml1s.miniscript.node.Terminal.OrI
import io.github.iml1s.miniscript.node.Terminal.Thresh
import io.github.iml1s.miniscript.node.Terminal.Multi
import io.github.iml1s.miniscript.node.Terminal.MultiA
import io.github.iml1s.miniscript.node.Terminal.Alt
import io.github.iml1s.miniscript.node.Terminal.Swap
import io.github.iml1s.miniscript.node.Terminal.Check
import io.github.iml1s.miniscript.node.Terminal.DupIf
import io.github.iml1s.miniscript.node.Terminal.Verify
import io.github.iml1s.miniscript.node.Terminal.NonZero
import io.github.iml1s.miniscript.node.Terminal.ZeroNotEqual
import io.github.iml1s.miniscript.parser.MiniscriptParser
import io.github.iml1s.miniscript.node.ScriptElt
import io.github.iml1s.miniscript.types.ExtData
import io.github.iml1s.miniscript.types.Type

/**
 * The top-level miniscript abstract syntax tree (AST).
 */
data class Miniscript<Pk : MiniscriptKey, Ctx : ScriptContext>(
    /** A node in the AST. */
    val node: Terminal<Pk, Ctx>,
    /** The correctness and malleability type information for the AST node. */
    val ty: Type,
    /** Additional information helpful for extra analysis. */
    val ext: ExtData
) {
    /**
     * Convert this miniscript to its equivalent bitcoin script elements.
     */
    fun toScript(): List<ScriptElt> = node.toScript()

    /**
     * Convert to the underlying bitcoin script bytes (as hex string).
     */
    fun scriptPubKey(): String {
        // Since we don't have a full ScriptWriter yet, let's just use toHexString on the list for now
        // or implement a simple byte encoder in ScriptElt.
        return toScript().joinToString("") {
             when (it) {
                 is ScriptElt.Op -> it.code.toString(16).padStart(2, '0')
                 is ScriptElt.Push -> {
                     val len = it.data.size
                     val prefix = when {
                         len < 0x4c -> len.toString(16).padStart(2, '0')
                         len <= 0xff -> "4c" + len.toString(16).padStart(2, '0')
                         len <= 0xffff -> "4d" + len.toString(16).padStart(2, '0') // Need byte order check
                         else -> "4e" + len.toString(16).padStart(2, '0')
                     }
                     prefix + it.data.joinToString("") { b -> b.toUByte().toString(16).padStart(2, '0') }
                 }
                 is ScriptElt.RawBytes -> it.bytes.joinToString("") { b -> b.toUByte().toString(16).padStart(2, '0') }
             }
        }
    }
    companion object {
        const val MAX_RECURSION_DEPTH = 402 // From rust-miniscript limits

        fun <Pk : MiniscriptKey, Ctx : ScriptContext> fromAst(t: Terminal<Pk, Ctx>): Miniscript<Pk, Ctx> {
             val ty = Type.typeCheck(t)
             val ext = ExtData.typeCheck(t) // Need to implement ExtData.typeCheck (or similar logic from Miniscript::from_ast in Rust)
             
             // Check recursion depth
             if (ext.treeHeight > MAX_RECURSION_DEPTH) {
                 throw RuntimeException("Max recursion depth exceeded")
             }
             
             // Check global validity (context dependent)
             // Ctx::check_global_validity(&res)?;
             // In Kotlin, Ctx is a reified type or instance? 
             // ScriptContext is an interface. We might need a companion object or instance passed in.
             // Or Miniscript constructor doesn't check it, but factories do.
             // For now, let's assume we can call it on a generic if we had reified instance, 
             // but here we are in a static context without Ctx instance.
             // We'll skip global validity for this simple factory for now, or require a context provider.
             
             return Miniscript(t, ty, ext)
        }
        /**
         * Parse a Miniscript from string and perform sanity checks.
         */
        fun <Pk : MiniscriptKey, Ctx : ScriptContext> fromStr(
            s: String,
            ctx: Ctx
        ): Miniscript<Pk, Ctx> {
            val tree = MiniscriptParser.parse(s)
            return fromTree(tree, ctx)
        }

        private fun <Pk : MiniscriptKey, Ctx : ScriptContext> fromTree(
            tree: io.github.iml1s.miniscript.parser.TokenTree,
            ctx: Ctx
        ): Miniscript<Pk, Ctx> {
            val parts = tree.name.split(':')
            val (wrappers, name) = if (parts.size == 2) {
                parts[0] to parts[1]
            } else {
                "" to parts[0]
            }

            var node: Terminal<Pk, Ctx> = when (name) {
                "0", "FALSE" -> False()
                "1", "TRUE" -> True()
                "pk_k" -> {
                    val keyStr = tree.children.firstOrNull()?.name
                        ?: throw IllegalArgumentException("pk_k requires 1 child")
                    @Suppress("UNCHECKED_CAST")
                    val key = ctx.parseKey(keyStr) as Pk
                    Terminal.PkK(key)
                }
                "pk" -> {
                    val keyStr = tree.children.firstOrNull()?.name
                        ?: throw IllegalArgumentException("pk requires 1 child")
                    @Suppress("UNCHECKED_CAST")
                    val key = ctx.parseKey(keyStr) as Pk
                    // pk(X) is an alias for c:pk_k(X)
                    // We can't return here because wrappers might need to be applied.
                    // Instead, we manually construct the 'c:' wrapped node and continue.
                    Terminal.Check(fromAst(Terminal.PkK(key)))
                }
                "and_v" -> {
                    checkChildren(tree, 2)
                    Terminal.AndV(
                        fromTree(tree.children[0], ctx),
                        fromTree(tree.children[1], ctx)
                    )
                }
                "and_b" -> {
                    checkChildren(tree, 2)
                    Terminal.AndB(
                        fromTree(tree.children[0], ctx),
                        fromTree(tree.children[1], ctx)
                    )
                }
                "or_b" -> {
                    checkChildren(tree, 2)
                    Terminal.OrB(
                        fromTree(tree.children[0], ctx),
                        fromTree(tree.children[1], ctx)
                    )
                }
                "or_d" -> {
                    checkChildren(tree, 2)
                    Terminal.OrD(
                        fromTree<Pk, Ctx>(tree.children[0], ctx),
                        fromTree<Pk, Ctx>(tree.children[1], ctx)
                    )
                }
                "or_c" -> {
                    checkChildren(tree, 2)
                    Terminal.OrC(
                        fromTree<Pk, Ctx>(tree.children[0], ctx),
                        fromTree<Pk, Ctx>(tree.children[1], ctx)
                    )
                }
                "or_i" -> {
                    checkChildren(tree, 2)
                    Terminal.OrI(
                        fromTree<Pk, Ctx>(tree.children[0], ctx),
                        fromTree<Pk, Ctx>(tree.children[1], ctx)
                    )
                }
                "andor" -> {
                    checkChildren(tree, 3)
                    Terminal.AndOr(
                        fromTree<Pk, Ctx>(tree.children[0], ctx),
                        fromTree<Pk, Ctx>(tree.children[1], ctx),
                        fromTree<Pk, Ctx>(tree.children[2], ctx)
                    )
                }
                "thresh" -> {
                    if (tree.children.isEmpty()) throw IllegalArgumentException("thresh requires at least k")
                    val k = tree.children[0].name.toIntOrNull()
                        ?: throw IllegalArgumentException("Invalid k for thresh")
                    val subs = tree.children.drop(1).map { fromTree<Pk, Ctx>(it, ctx) }
                    Terminal.Thresh(Threshold(k, subs))
                }
                "multi" -> {
                    if (tree.children.isEmpty()) throw IllegalArgumentException("multi requires at least k")
                    val k = tree.children[0].name.toIntOrNull()
                        ?: throw IllegalArgumentException("Invalid k for multi")
                    val keys = tree.children.drop(1).map {
                        @Suppress("UNCHECKED_CAST")
                        ctx.parseKey(it.name) as Pk
                    }
                    Terminal.Multi(Threshold(k, keys))
                }
                 // Timelocks
                "after" -> {
                     checkChildren(tree, 1)
                     val time = tree.children[0].name.toUIntOrNull() ?: throw IllegalArgumentException("Invalid time")
                     Terminal.After(AbsLockTime(time))
                }
                "older" -> {
                    checkChildren(tree, 1)
                    val time = tree.children[0].name.toUIntOrNull() ?: throw IllegalArgumentException("Invalid time")
                    Terminal.Older(RelLockTime(time))
                }
                "pkh" -> {
                    checkChildren(tree, 1)
                    val keyStr = tree.children[0].name
                    @Suppress("UNCHECKED_CAST")
                    val key = ctx.parseKey(keyStr) as Pk
                    Terminal.PkH(key)
                }
                // Hashes
                "sha256" -> {
                    checkChildren(tree, 1)
                    Terminal.Sha256(io.github.iml1s.crypto.Hex.decode(tree.children[0].name))
                }
                "hash256" -> {
                    checkChildren(tree, 1)
                    Terminal.Hash256(io.github.iml1s.crypto.Hex.decode(tree.children[0].name))
                }
                "ripemd160" -> {
                    checkChildren(tree, 1)
                    Terminal.Ripemd160(io.github.iml1s.crypto.Hex.decode(tree.children[0].name))
                }
                "hash160" -> {
                    checkChildren(tree, 1)
                    Terminal.Hash160(io.github.iml1s.crypto.Hex.decode(tree.children[0].name))
                }
                 // ... other fragments
                else -> throw IllegalArgumentException("Unknown fragment: $name")
            }

            // Apply wrappers in reverse order
            for (char in wrappers.reversed()) {
                node = when (char) {
                    'a' -> Terminal.Alt(fromAst(node))
                    's' -> Terminal.Swap(fromAst(node))
                    'c' -> Terminal.Check(fromAst(node))
                    'd' -> Terminal.DupIf(fromAst(node))
                    'v' -> Terminal.Verify(fromAst(node))
                    'j' -> Terminal.NonZero(fromAst(node))
                    'n' -> Terminal.ZeroNotEqual(fromAst(node))
                    't' -> Terminal.AndV(fromAst(node), fromAst(True()))
                    'u' -> Terminal.OrI(fromAst(node), fromAst(False()))
                    'l' -> Terminal.OrI(fromAst(False()), fromAst(node))
                    else -> throw IllegalArgumentException("Unknown wrapper: $char")
                }
            }

            return fromAst(node)
        }

        private fun checkChildren(tree: io.github.iml1s.miniscript.parser.TokenTree, count: Int) {
            if (tree.children.size != count) {
                throw IllegalArgumentException("${tree.name} requires $count children, got ${tree.children.size}")
            }
        }
    }
}
