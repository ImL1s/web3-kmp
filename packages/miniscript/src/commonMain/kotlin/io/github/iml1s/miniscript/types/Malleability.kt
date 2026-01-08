package io.github.iml1s.miniscript.types

import io.github.iml1s.miniscript.MiniscriptError

/**
 * Whether the fragment has a dissatisfaction, and if so, whether
 * it is unique.
 *
 * Affects both correctness and malleability-freeness,
 * since we assume 3rd parties are able to produce dissatisfactions
 * for all fragments.
 */
enum class Dissat {
    /**
     * Fragment has no dissatisfactions and will abort given non-satisfying
     * input.
     */
    None,
    /**
     * Fragment has a unique dissatisfaction, which is always available,
     * and will push 0 given this dissatisfaction as input.
     *
     * The combination
     * of `Dissat::Unique` and `Input::Zero` implies that a fragment is
     * impossible to satisfy (is a `0` or equivalent).
     */
    Unique,
    /**
     * No assumptions may be made about dissatisfying this fragment.
     *
     * This
     * does not necessarily mean that there are multiple dissatisfactions;
     * there may be none, or none that are always available (e.g. for a
     * `pk_h` the key preimage may not be available).
     */
    Unknown;

    /**
     * Check whether given `Dissat` is a subtype of `other`. That is,
     * if some Dissat is `Unique` then it must be `Unknown`.
     */
    fun isSubtype(other: Dissat): Boolean {
        if (this == other) return true
        return other == Unknown
    }
}

/**
 * Structure representing the type properties of a fragment which have
 * relevance to malleability analysis
 */
data class Malleability(
    /** Properties of dissatisfying inputs */
    val dissat: Dissat,
    /**
     * `true` if satisfactions cannot be created by any 3rd party
     * who has not yet seen a satisfaction.
     *
     * Hash preimages and signature checks are safe; timelocks are not. Affects
     * malleability.
     */
    val safe: Boolean,
    /**
     * Whether a non-malleable satisfaction is guaranteed to exist for
     * the fragment
     */
    val nonMalleable: Boolean
) {
    /**
     * Check whether the `self` is a subtype of `other` argument.
     *
     * This checks whether the argument `other` has attributes which are present
     * in the given `Type`. This returns `true` on same arguments
     * `a.isSubtype(a)` is `true`.
     */
    fun isSubtype(other: Malleability): Boolean {
        return this.dissat.isSubtype(other.dissat) &&
                (if (this.safe) 1 else 0) >= (if (other.safe) 1 else 0) &&
                (if (this.nonMalleable) 1 else 0) >= (if (other.nonMalleable) 1 else 0)
    }

    fun castAlt() = this
    fun castSwap() = this
    fun castCheck() = this

    fun castDupIf(): Malleability {
        val newDissat = if (this.dissat == Dissat.None) Dissat.Unique else Dissat.Unknown
        return copy(dissat = newDissat)
    }

    fun castVerify(): Malleability {
        return copy(dissat = Dissat.None)
    }

    fun castNonZero(): Malleability {
        val newDissat = if (this.dissat == Dissat.None) Dissat.Unique else Dissat.Unknown
        return copy(dissat = newDissat)
    }

    fun castZeroNotEqual() = this

    fun castTrue(): Malleability {
        return copy(dissat = Dissat.None)
    }

    fun castOrIFalse(): Malleability {
        val newDissat = if (this.dissat == Dissat.None) Dissat.Unique else Dissat.Unknown
        return copy(dissat = newDissat)
    }
    
    companion object {
        val TRUE = Malleability(Dissat.None, safe = false, nonMalleable = true)
        val FALSE = Malleability(Dissat.Unique, safe = true, nonMalleable = true)

        fun pkK() = Malleability(Dissat.Unique, safe = true, nonMalleable = true)
        fun pkH() = Malleability(Dissat.Unique, safe = true, nonMalleable = true)
        fun multi() = Malleability(Dissat.Unique, safe = true, nonMalleable = true)
        fun multiA() = Malleability(Dissat.Unique, safe = true, nonMalleable = true)
        fun hash() = Malleability(Dissat.Unknown, safe = false, nonMalleable = true)
        fun time() = Malleability(Dissat.None, safe = false, nonMalleable = true)

        fun andB(left: Malleability, right: Malleability): Malleability {
            val dissat = when (Pair(left.dissat, right.dissat)) {
                Pair(Dissat.None, Dissat.None) -> Dissat.None
                Pair(Dissat.None, Dissat.Unique), Pair(Dissat.None, Dissat.Unknown) -> if (left.safe) Dissat.None else Dissat.Unknown 
                Pair(Dissat.Unique, Dissat.None), Pair(Dissat.Unknown, Dissat.None) -> if (right.safe) Dissat.None else Dissat.Unknown
                Pair(Dissat.Unique, Dissat.Unique) -> if (left.safe && right.safe) Dissat.Unique else Dissat.Unknown
                else -> Dissat.Unknown
            }
            return Malleability(dissat, left.safe || right.safe, left.nonMalleable && right.nonMalleable)
        }

        fun andV(left: Malleability, right: Malleability): Malleability {
            val dissat = when {
                 right.dissat == Dissat.None -> Dissat.None
                 left.safe -> Dissat.None
                 else -> Dissat.Unknown
            }
            return Malleability(dissat, left.safe || right.safe, left.nonMalleable && right.nonMalleable)
        }

        fun orB(left: Malleability, right: Malleability): Malleability {
            return Malleability(
                Dissat.Unique,
                left.safe && right.safe,
                left.nonMalleable && left.dissat == Dissat.Unique &&
                        right.nonMalleable && right.dissat == Dissat.Unique &&
                        (left.safe || right.safe)
            )
        }

        fun orD(left: Malleability, right: Malleability): Malleability {
            return Malleability(
                right.dissat,
                left.safe && right.safe,
                left.nonMalleable && left.dissat == Dissat.Unique &&
                        right.nonMalleable && (left.safe || right.safe)
            )
        }

        fun orC(left: Malleability, right: Malleability): Malleability {
            return Malleability(
                Dissat.None,
                left.safe && right.safe,
                left.nonMalleable && left.dissat == Dissat.Unique &&
                        right.nonMalleable && (left.safe || right.safe)
            )
        }
        
        fun orI(left: Malleability, right: Malleability): Malleability {
            val dissat = when (Pair(left.dissat, right.dissat)) {
                Pair(Dissat.None, Dissat.None) -> Dissat.None
                Pair(Dissat.Unique, Dissat.None) -> Dissat.Unique
                Pair(Dissat.None, Dissat.Unique) -> Dissat.Unique
                else -> Dissat.Unknown
            }
            val safe = left.safe && right.safe
            return Malleability(dissat, safe, left.nonMalleable && right.nonMalleable && safe)
        }

        fun andOr(a: Malleability, b: Malleability, c: Malleability): Malleability {
             val dissat = when {
                 // (_, Dissat::None, Dissat::Unique) => Dissat::Unique
                 b.dissat == Dissat.None && c.dissat == Dissat.Unique -> Dissat.Unique
                 // (true, _, Dissat::Unique) => Dissat::Unique
                 a.safe && c.dissat == Dissat.Unique -> Dissat.Unique
                 // (_, Dissat::None, Dissat::None) => Dissat::None
                 b.dissat == Dissat.None && c.dissat == Dissat.None -> Dissat.None
                 // (true, _, Dissat::None) => Dissat::None
                 a.safe && c.dissat == Dissat.None -> Dissat.None
                 else -> Dissat.Unknown
             }
             return Malleability(
                 dissat,
                 (a.safe || b.safe) && c.safe,
                 a.nonMalleable && c.nonMalleable && a.dissat == Dissat.Unique &&
                         b.nonMalleable && (a.safe || b.safe || c.safe)
             )
        }

        fun threshold(k: Int, subs: List<Malleability>): Malleability {
            val n = subs.size
            var safeCount = 0
            var allAreDissatUnique = true
            var allAreNonMalleable = true
            subs.forEach { subtype ->
                if (subtype.safe) safeCount += 1
                if (subtype.dissat != Dissat.Unique) allAreDissatUnique = false
                if (!subtype.nonMalleable) allAreNonMalleable = false
            }

            val dissat = if (allAreDissatUnique && safeCount == n) Dissat.Unique else Dissat.Unknown
            val safe = safeCount > n - k
            return Malleability(dissat, safe, allAreNonMalleable && safeCount >= n - k && allAreDissatUnique)
        }
    }
}
