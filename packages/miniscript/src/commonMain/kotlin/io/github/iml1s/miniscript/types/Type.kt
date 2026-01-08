package io.github.iml1s.miniscript.types

import io.github.iml1s.miniscript.MiniscriptError

/**
 * Structure representing the type of a Miniscript fragment, including all
 * properties relevant to the main codebase
 */
data class Type(
    /** Correctness/soundness properties */
    val corr: Correctness,
    /** Malleability properties */
    val mall: Malleability
) {
    /**
     * Check whether the `self` is a subtype of `other` argument .
     * This checks whether the argument `other` has attributes which are present
     * in the given `Type`. This returns `true` on same arguments
     * `a.isSubtype(a)` is `true`.
     */
    fun isSubtype(other: Type): Boolean {
        return this.corr.isSubtype(other.corr) && this.mall.isSubtype(other.mall)
    }

    /**
     * Confirm invariants of the type checker.
     */
    fun sanityChecks() {
        if (this.corr.dissatisfiable && this.mall.dissat == Dissat.None) {
            throw AssertionError("Dissatisfiable but Dissat is None")
        }
        if (this.mall.dissat != Dissat.None && this.corr.base == Base.V) {
             throw AssertionError("Dissat is not None but Base is V")
        }
        if (!this.mall.safe && this.corr.base == Base.K) {
             throw AssertionError("Not safe but Base is K")
        }
        if (!this.mall.nonMalleable && this.corr.input == Input.Zero) {
             throw AssertionError("Malleable but Input is Zero")
        }
        this.corr.sanityChecks()
    }

    fun castAlt(): Type {
        return Type(this.corr.castAlt(), this.mall.castAlt())
    }

    fun castSwap(): Type {
        return Type(this.corr.castSwap(), this.mall.castSwap())
    }

    fun castCheck(): Type {
        return Type(this.corr.castCheck(), this.mall.castCheck())
    }

    fun castDupIf(): Type {
        return Type(this.corr.castDupIf(), this.mall.castDupIf())
    }

    fun castVerify(): Type {
        return Type(this.corr.castVerify(), this.mall.castVerify())
    }

    fun castNonZero(): Type {
        return Type(this.corr.castNonZero(), this.mall.castNonZero())
    }

    fun castZeroNotEqual(): Type {
        return Type(this.corr.castZeroNotEqual(), this.mall.castZeroNotEqual())
    }

    fun castTrue(): Type {
        return Type(this.corr.castTrue(), this.mall.castTrue())
    }

    fun castUnlikely(): Type {
        return Type(this.corr.castOrIFalse(), this.mall.castOrIFalse())
    }

    fun castLikely(): Type {
        return Type(this.corr.castOrIFalse(), this.mall.castOrIFalse())
    }

    companion object {
        val TRUE = Type(Correctness.TRUE, Malleability.TRUE)
        val FALSE = Type(Correctness.FALSE, Malleability.FALSE)

        fun pkK() = Type(Correctness.pkK(), Malleability.pkK())
        fun pkH() = Type(Correctness.pkH(), Malleability.pkH())
        fun multi() = Type(Correctness.multi(), Malleability.multi())
        fun multiA() = Type(Correctness.multiA(), Malleability.multiA())
        fun hash() = Type(Correctness.hash(), Malleability.hash())
        fun time() = Type(Correctness.time(), Malleability.time())

        fun andB(left: Type, right: Type): Type {
            return Type(Correctness.andB(left.corr, right.corr), Malleability.andB(left.mall, right.mall))
        }

        fun andV(left: Type, right: Type): Type {
            return Type(Correctness.andV(left.corr, right.corr), Malleability.andV(left.mall, right.mall))
        }

        fun orB(left: Type, right: Type): Type {
            return Type(Correctness.orB(left.corr, right.corr), Malleability.orB(left.mall, right.mall))
        }

        fun orD(left: Type, right: Type): Type {
            return Type(Correctness.orD(left.corr, right.corr), Malleability.orD(left.mall, right.mall))
        }

        fun orC(left: Type, right: Type): Type {
            return Type(Correctness.orC(left.corr, right.corr), Malleability.orC(left.mall, right.mall))
        }

        fun orI(left: Type, right: Type): Type {
            return Type(Correctness.orI(left.corr, right.corr), Malleability.orI(left.mall, right.mall))
        }

        fun andOr(a: Type, b: Type, c: Type): Type {
            return Type(Correctness.andOr(a.corr, b.corr, c.corr), Malleability.andOr(a.mall, b.mall, c.mall))
        }

        fun threshold(k: Int, subs: List<Type>): Type {
            return Type(Correctness.threshold(k, subs.map { it.corr }), Malleability.threshold(k, subs.map { it.mall }))
        }

        fun <Pk : io.github.iml1s.miniscript.MiniscriptKey, Ctx : io.github.iml1s.miniscript.context.ScriptContext> typeCheck(t: io.github.iml1s.miniscript.node.Terminal<Pk, Ctx>): Type {
            return when (t) {
                is io.github.iml1s.miniscript.node.Terminal.True -> TRUE
                is io.github.iml1s.miniscript.node.Terminal.False -> FALSE
                is io.github.iml1s.miniscript.node.Terminal.PkK -> pkK()
                is io.github.iml1s.miniscript.node.Terminal.PkH -> pkH()
                is io.github.iml1s.miniscript.node.Terminal.RawPkH -> pkH()
                is io.github.iml1s.miniscript.node.Terminal.After -> time()
                is io.github.iml1s.miniscript.node.Terminal.Older -> time()
                is io.github.iml1s.miniscript.node.Terminal.Sha256 -> hash()
                is io.github.iml1s.miniscript.node.Terminal.Hash256 -> hash()
                is io.github.iml1s.miniscript.node.Terminal.Ripemd160 -> hash()
                is io.github.iml1s.miniscript.node.Terminal.Hash160 -> hash()
                is io.github.iml1s.miniscript.node.Terminal.Alt -> t.sub.ty.castAlt()
                is io.github.iml1s.miniscript.node.Terminal.Swap -> t.sub.ty.castSwap()
                is io.github.iml1s.miniscript.node.Terminal.Check -> t.sub.ty.castCheck()
                is io.github.iml1s.miniscript.node.Terminal.DupIf -> t.sub.ty.castDupIf()
                is io.github.iml1s.miniscript.node.Terminal.Verify -> t.sub.ty.castVerify()
                is io.github.iml1s.miniscript.node.Terminal.NonZero -> t.sub.ty.castNonZero()
                is io.github.iml1s.miniscript.node.Terminal.ZeroNotEqual -> t.sub.ty.castZeroNotEqual()
                is io.github.iml1s.miniscript.node.Terminal.AndV -> andV(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.AndB -> andB(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.AndOr -> andOr(t.a.ty, t.b.ty, t.c.ty)
                is io.github.iml1s.miniscript.node.Terminal.OrB -> orB(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.OrD -> orD(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.OrC -> orC(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.OrI -> orI(t.l.ty, t.r.ty)
                is io.github.iml1s.miniscript.node.Terminal.Thresh -> threshold(t.thresh.k, t.thresh.data.map { it.ty })
                is io.github.iml1s.miniscript.node.Terminal.Multi -> multi()
                is io.github.iml1s.miniscript.node.Terminal.MultiA -> multiA()
            }
        }
    }
}
