package io.github.iml1s.miniscript.context

import io.github.iml1s.miniscript.MiniscriptKey

/**
 * ScriptContext determines which features are allowed in the Miniscript.
 */
interface ScriptContext {
    val name: String
    
    // In Rust, this has associated types: Key : MiniscriptKey
    // We can simulate this with generics if needed, or just standard types.
    // But keeping it simple for now.

    fun checkGlobalValidity(miniscript: Any) // Placeholder for Miniscript object
    
    fun maxSatisfactionSize(miniscript: Any): Int?
    
    fun pkLen(pk: MiniscriptKey): Int
    
    fun parseKey(s: String): MiniscriptKey
    
    companion object {
        fun nameStr(ctx: ScriptContext): String = ctx.name
    }
}

object BareCtx : ScriptContext {
    override val name: String = "Bare"
    override fun checkGlobalValidity(miniscript: Any) {}
    override fun maxSatisfactionSize(miniscript: Any): Int? = null // TODO
    override fun pkLen(pk: MiniscriptKey): Int = if (pk.isUncompressed) 65 else 33
    override fun parseKey(s: String): MiniscriptKey = io.github.iml1s.miniscript.StringKey(s)
}

object Segwitv0 : ScriptContext {
    override val name: String = "Segwitv0"
    override fun checkGlobalValidity(miniscript: Any) {}
    override fun maxSatisfactionSize(miniscript: Any): Int? = null // TODO
    override fun pkLen(pk: MiniscriptKey): Int = 33 // Compressed only
    override fun parseKey(s: String): MiniscriptKey = io.github.iml1s.miniscript.StringKey(s)
}

object Tap : ScriptContext {
    override val name: String = "Taproot"
    override fun checkGlobalValidity(miniscript: Any) {}
    override fun maxSatisfactionSize(miniscript: Any): Int? = null // TODO
    override fun pkLen(pk: MiniscriptKey): Int = 32 // X-only
    override fun parseKey(s: String): MiniscriptKey = io.github.iml1s.miniscript.StringKey(s)
}

object Legacy : ScriptContext {
    override val name: String = "Legacy"
    override fun checkGlobalValidity(miniscript: Any) {}
    override fun maxSatisfactionSize(miniscript: Any): Int? = null // TODO
    override fun pkLen(pk: MiniscriptKey): Int = if (pk.isUncompressed) 65 else 33
    override fun parseKey(s: String): MiniscriptKey = io.github.iml1s.miniscript.StringKey(s)
}
