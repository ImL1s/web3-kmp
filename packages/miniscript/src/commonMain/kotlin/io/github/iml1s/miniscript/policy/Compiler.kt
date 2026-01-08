package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.Miniscript
import io.github.iml1s.miniscript.MiniscriptKey
import io.github.iml1s.miniscript.context.BareCtx
import io.github.iml1s.miniscript.context.ScriptContext
import io.github.iml1s.miniscript.node.Terminal
import io.github.iml1s.miniscript.types.Correctness
import io.github.iml1s.miniscript.types.Type

/**
 * Extension to compile a Concrete Policy into a Miniscript.
 * Currently defaults to BareCtx.
 */
fun <Pk : MiniscriptKey> Concrete<Pk>.compile(): Miniscript<Pk, BareCtx> {
    return Miniscript.fromAst(this.toTerminal())
}

private fun <Pk : MiniscriptKey> Concrete<Pk>.toTerminal(): Terminal<Pk, BareCtx> {
    return when (this) {
        is Concrete.Trivial -> Terminal.True()
        is Concrete.Unsatisfiable -> Terminal.False()
        is Concrete.Key -> Terminal.Check(Miniscript.fromAst(Terminal.PkK(key)))
        is Concrete.After -> Terminal.After(lockTime)
        is Concrete.Older -> Terminal.Older(lockTime)
        is Concrete.Sha256 -> Terminal.Sha256(hash)
        is Concrete.Hash256 -> Terminal.Hash256(hash)
        is Concrete.Ripemd160 -> Terminal.Ripemd160(hash)
        is Concrete.Hash160 -> Terminal.Hash160(hash)
        is Concrete.And -> compileAnd(subs)
        is Concrete.Or -> compileOr(subs)
        is Concrete.Thresh -> compileThresh(threshold.k, threshold.data)
    }
}

private fun <Pk : MiniscriptKey> compileAnd(subs: List<Concrete<Pk>>): Terminal<Pk, BareCtx> {
    if (subs.isEmpty()) return Terminal.True()
    
    val compiledSubs = subs.map { Miniscript.fromAst(it.toTerminal()) }
    var acc = compiledSubs[0]
    
    for (i in 1 until compiledSubs.size) {
        val next = compiledSubs[i]
        // and_b requires (B, W)
        val left = acc.asB()
        val right = next.asW()
        acc = Miniscript.fromAst(Terminal.AndB(left, right))
    }
    return acc.node
}

private fun <Pk : MiniscriptKey> compileOr(subs: List<Pair<UInt, Concrete<Pk>>>): Terminal<Pk, BareCtx> {
    if (subs.isEmpty()) return Terminal.False()
    
    val compiledSubs = subs.map { Miniscript.fromAst(it.second.toTerminal()) }
    var acc = compiledSubs[0]
    
    for (i in 1 until compiledSubs.size) {
        val next = compiledSubs[i]
        // Strategy: or_d (Dissatisfiable OR)
        // or_d(x, y) = <x> IFDUP NOTIF <y> ENDIF
        // Requires: x is disatisfiable and unit (Base B). y is Base B.
        // This is generally more efficient and easier to satisfy than or_b (which needs W) for standard policies.
        val left = acc.asB()
        val right = next.asB()
        acc = Miniscript.fromAst(Terminal.OrD(left, right))
    }
    return acc.node
}

private fun <Pk : MiniscriptKey> compileThresh(k: Int, subs: List<Concrete<Pk>>): Terminal<Pk, BareCtx> {
    val compiledSubs = subs.mapIndexed { index, sub -> 
        val m = Miniscript.fromAst(sub.toTerminal())
        if (index == 0) m.asB() else m.asW()
    }
    return Terminal.Thresh(io.github.iml1s.miniscript.Threshold(k, compiledSubs))
}

// Type casting helpers

private fun <Pk : MiniscriptKey> Miniscript<Pk, BareCtx>.asB(): Miniscript<Pk, BareCtx> {
    return when (this.ty.corr.base) {
        io.github.iml1s.miniscript.types.Base.B -> this
        io.github.iml1s.miniscript.types.Base.K -> Miniscript.fromAst(Terminal.Check(this)) // K -> B (Check)
        // V -> B is complicated. Assuming we don't produce V usually in compilation from Concrete unless optimized.
        else -> this 
    }
}

private fun <Pk : MiniscriptKey> Miniscript<Pk, BareCtx>.asW(): Miniscript<Pk, BareCtx> {
    return when (this.ty.corr.base) {
        io.github.iml1s.miniscript.types.Base.W -> this
        io.github.iml1s.miniscript.types.Base.B -> Miniscript.fromAst(Terminal.Alt(this)) // B -> W (Alt)
        io.github.iml1s.miniscript.types.Base.K -> Miniscript.fromAst(Terminal.Alt(Miniscript.fromAst(Terminal.Check(this)))) // K -> B -> W
        else -> this
    }
}
