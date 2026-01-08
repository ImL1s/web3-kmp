package io.github.iml1s.miniscript.parser

import io.github.iml1s.miniscript.*
import io.github.iml1s.miniscript.context.*

/**
 * Parser for Bitcoin Output Descriptors.
 */
object DescriptorParser {

    /**
     * Parse a descriptor string into a Descriptor object.
     */
    fun <Pk : MiniscriptKey> parse(s: String, ctx: ScriptContext): Descriptor<Pk> {
        // Strip checksum if present
        val mainPart = if (s.contains('#')) {
            s.split('#')[0]
        } else {
            s
        }

        val tree = TokenTreeParser.parse(mainPart)
        return fromTree(tree, ctx)
    }

    private fun <Pk : MiniscriptKey> fromTree(tree: TokenTree, ctx: ScriptContext): Descriptor<Pk> {
        return when (tree.name) {
            "pkh" -> {
                checkChildren(tree, 1)
                @Suppress("UNCHECKED_CAST")
                val key = ctx.parseKey(tree.children[0].name) as Pk
                Descriptor.Pkh(key)
            }
            "pk" -> {
                checkChildren(tree, 1)
                @Suppress("UNCHECKED_CAST")
                val key = ctx.parseKey(tree.children[0].name) as Pk
                Descriptor.Pk(key)
            }
            "wpkh" -> {
                checkChildren(tree, 1)
                @Suppress("UNCHECKED_CAST")
                val key = ctx.parseKey(tree.children[0].name) as Pk
                Descriptor.Wpkh(key)
            }
            "multi", "sortedmulti" -> {
                if (tree.children.size < 2) throw IllegalArgumentException("${tree.name} requires at least threshold and one key")
                val threshold = tree.children[0].name.toInt()
                val keys = mutableListOf<Pk>()
                for (i in 1 until tree.children.size) {
                    @Suppress("UNCHECKED_CAST")
                    keys.add(ctx.parseKey(tree.children[i].name) as Pk)
                }
                if (tree.name == "multi") Descriptor.Multi(threshold, keys)
                else Descriptor.SortedMulti(threshold, keys)
            }
            "sh" -> {
                checkChildren(tree, 1)
                val sub = fromTree<Pk>(tree.children[0], ctx)
                Descriptor.Sh(sub)
            }
            "wsh" -> {
                checkChildren(tree, 1)
                // For wsh, the content is a Miniscript with Segwitv0
                // Use toString() to get the full expression inside wsh(...)
                val miniscriptStr = tree.children[0].toString()
                val miniscript = Miniscript.fromStr<Pk, Segwitv0>(miniscriptStr, Segwitv0)
                Descriptor.Wsh(miniscript)
            }
            "tr" -> {
                if (tree.children.isEmpty()) throw IllegalArgumentException("tr requires at least an internal key")
                @Suppress("UNCHECKED_CAST")
                val internalKey = ctx.parseKey(tree.children[0].name) as Pk
                
                val tapTree = if (tree.children.size > 1) {
                    parseTapTree<Pk>(tree.children[1], ctx)
                } else {
                    null
                }
                Descriptor.Tr(internalKey, tapTree)
            }
            "addr" -> {
                checkChildren(tree, 1)
                Descriptor.Addr(tree.children[0].name)
            }
            "raw" -> {
                checkChildren(tree, 1)
                Descriptor.Raw(tree.children[0].name)
            }
            else -> throw IllegalArgumentException("Unknown descriptor type: ${tree.name}")
        }
    }

    private fun <Pk : MiniscriptKey> parseTapTree(tree: TokenTree, ctx: ScriptContext): TapTree {
        return if (tree.name == "{") {
            if (tree.children.size != 2) throw IllegalArgumentException("Taproot tree branch must have exactly 2 children")
            TapTree.Branch(
                parseTapTree<Pk>(tree.children[0], ctx),
                parseTapTree<Pk>(tree.children[1], ctx)
            )
        } else {
            // It's a leaf descriptor
            val desc = fromTree<Pk>(tree, ctx)
            TapTree.Leaf(desc.scriptPubKey()) // Version 0xc0 default
        }
    }

    private fun checkChildren(tree: TokenTree, count: Int) {
        if (tree.children.size != count) {
            throw IllegalArgumentException("${tree.name} requires $count children, got ${tree.children.size}")
        }
    }
}

/**
 * Re-exporting or moving TokenTree and Parser if they are generic enough
 */
private typealias TokenTreeParser = MiniscriptParser
