package io.github.iml1s.miniscript.types

import io.github.iml1s.miniscript.MiniscriptError

/**
 * Basic type representing where the fragment can go
 */
enum class Base {
    /**
     * Takes its inputs from the top of the stack. Pushes
     * nonzero if the condition is satisfied. If not, if it
     * does not abort, then 0 is pushed.
     */
    B,
    /**
     * Takes its inputs from the top of the stack. Pushes a
     * public key, regardless of satisfaction, onto the stack.
     * Must be wrapped in `c:` to turn into any other type.
     */
    K,
    /**
     * Takes its inputs from the top of the stack, which
     * must satisfy the condition (will abort otherwise).
     * Does not push anything onto the stack.
     */
    V,
    /**
     * Takes from the stack its inputs + element X at the top.
     * If the inputs satisfy the condition, [nonzero X] or
     * [X nonzero] is pushed. If not, if it does not abort,
     * then [0 X] or [X 0] is pushed.
     */
    W;
}

/**
 * Type property representing expectations about how many inputs
 * the fragment accepts, and assumptions about that
 */
enum class Input {
    /** Consumes no stack elements under any circumstances */
    Zero,
    /** Consumes exactly one stack element under all circumstances */
    One,
    /** Consumes any number of stack elements */
    Any,
    /**
     * Consumes exactly one stack element. If the fragment is
     * satisfied, this element must be nonzero.
     */
    OneNonZero,
    /**
     * Consumes 1 or more stack elements. If the fragment is
     * satisfied, the top element must be nonzero. (This property
     * cannot be applied to any type with a `W` base.)
     */
    AnyNonZero;

    /**
     * Check whether given `Input` is a subtype of `other`. That is,
     * if some Input is `OneNonZero` then it must be `One`, hence `OneNonZero` is
     * a subtype if `One`. Returns `true` for `a.isSubtype(a)`.
     */
    fun isSubtype(other: Input): Boolean {
        if (this == other) return true
        return when (other) {
            One -> this == OneNonZero
            AnyNonZero -> this == OneNonZero
            Any -> true
            else -> false
        }
    }
}

/**
 * Soundness and completeness type properties of a fragment.
 *
 * Completeness is the property that a valid witness actually exists for all
 * branches, which an honest user can produce. Soundness is the property
 * that no branch can be satisfied _without_ an honest user.
 */
data class Correctness(
    /** The base type */
    val base: Base,
    /** Properties of the inputs */
    val input: Input,
    /**
     * Whether it is definitely possible to dissatisfy the expression.
     * If this is false, it does not necessarily mean that dissatisfaction
     * is impossible (see `Dissat::None` for this property); it only means
     * that we cannot depend on having a dissatisfaction when reasoning
     * about completeness.
     */
    val dissatisfiable: Boolean,
    /**
     * Whether the fragment's "nonzero" output on satisfaction is
     * always the constant 1.
     */
    val unit: Boolean
) {
    /**
     * Check whether the `self` is a subtype of `other` argument .
     * This checks whether the argument `other` has attributes which are present
     * in the given `Correctness`. This returns `true` on same arguments
     * `a.isSubtype(a)` is `true`.
     */
    fun isSubtype(other: Correctness): Boolean {
        return this.base == other.base &&
                this.input.isSubtype(other.input) &&
                (if (this.dissatisfiable) 1 else 0) >= (if (other.dissatisfiable) 1 else 0) &&
                (if (this.unit) 1 else 0) >= (if (other.unit) 1 else 0)
    }

    /**
     * Confirm invariants of the correctness checker.
     */
    fun sanityChecks() {
        when (this.base) {
            Base.B -> {}
            Base.K -> {
                // debug_assert!(self.unit);
                 if (!this.unit) throw AssertionError("Base K must be unit")
            }
            Base.V -> {
                // debug_assert!(!self.unit);
                // debug_assert!(!self.dissatisfiable);
                if (this.unit) throw AssertionError("Base V must not be unit")
                if (this.dissatisfiable) throw AssertionError("Base V must not be dissatisfiable")
            }
            Base.W -> {
                // debug_assert!(!self.input.constfn_eq(Input::OneNonZero));
                // debug_assert!(!self.input.constfn_eq(Input::AnyNonZero));
                if (this.input == Input.OneNonZero) throw AssertionError("Base W cannot have OneNonZero input")
                if (this.input == Input.AnyNonZero) throw AssertionError("Base W cannot have AnyNonZero input")
            }
        }
    }

    fun castAlt(): Correctness {
        // base check 1
        return when (this.base) {
            Base.B -> copy(base = Base.W, input = Input.Any)
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
    }

    fun castSwap(): Correctness {
         val newBase = when (this.base) {
             Base.B -> Base.W
             else -> throw MiniscriptError.ChildBase1(this.base)
         }
         val newInput = when (this.input) {
             Input.One, Input.OneNonZero -> Input.Any
             else -> throw MiniscriptError.SwapNonOne
         }
         return copy(base = newBase, input = newInput)
    }

    fun castCheck(): Correctness {
        val newBase = when (this.base) {
            Base.K -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        return copy(base = newBase, unit = true)
    }

    fun castDupIf(): Correctness {
        val newBase = when (this.base) {
            Base.V -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        val newInput = when (this.input) {
            Input.Zero -> Input.OneNonZero
            else -> throw MiniscriptError.NonZeroDupIf
        }
        return copy(base = newBase, input = newInput, dissatisfiable = true, unit = false)
    }

    fun castVerify(): Correctness {
        val newBase = when (this.base) {
            Base.B, Base.K, Base.W -> Base.V
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        return copy(base = newBase, dissatisfiable = false, unit = false)
    }

    fun castNonZero(): Correctness {
        if (this.input != Input.OneNonZero && this.input != Input.AnyNonZero) {
            throw MiniscriptError.NonZeroZero
        }
        val newBase = when (this.base) {
            Base.B -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        return copy(base = newBase, dissatisfiable = true)
    }

    fun castZeroNotEqual(): Correctness {
        val newBase = when (this.base) {
            Base.B -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        return copy(base = newBase, unit = true)
    }

    fun castTrue(): Correctness {
        val newBase = when (this.base) {
            Base.V -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        return copy(base = newBase, dissatisfiable = false, unit = true)
    }

    fun castOrIFalse(): Correctness {
        val newBase = when (this.base) {
            Base.B -> Base.B
            else -> throw MiniscriptError.ChildBase1(this.base)
        }
        val newInput = when (this.input) {
            Input.Zero -> Input.One
            else -> Input.Any
        }
        return copy(base = newBase, input = newInput, dissatisfiable = true)
    }


    companion object {
        val TRUE = Correctness(Base.B, Input.Zero, dissatisfiable = false, unit = true)
        val FALSE = Correctness(Base.B, Input.Zero, dissatisfiable = true, unit = true)

        fun pkK() = Correctness(Base.K, Input.OneNonZero, dissatisfiable = true, unit = true)
        fun pkH() = Correctness(Base.K, Input.AnyNonZero, dissatisfiable = true, unit = true)
        fun multi() = Correctness(Base.B, Input.AnyNonZero, dissatisfiable = true, unit = true)
        fun multiA() = Correctness(Base.B, Input.Any, dissatisfiable = true, unit = true)
        fun hash() = Correctness(Base.B, Input.OneNonZero, dissatisfiable = true, unit = true)
        fun time() = Correctness(Base.B, Input.Zero, dissatisfiable = false, unit = false)

        fun andB(left: Correctness, right: Correctness): Correctness {
            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.B, Base.W) -> Base.B
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = matchInputs(left.input, right.input)
            return Correctness(newBase, newInput, left.dissatisfiable && right.dissatisfiable, unit = true)
        }

        fun andV(left: Correctness, right: Correctness): Correctness {
            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.V, Base.B) -> Base.B
                Pair(Base.V, Base.K) -> Base.K
                Pair(Base.V, Base.V) -> Base.V
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = matchInputs(left.input, right.input)
            return Correctness(newBase, newInput, dissatisfiable = false, unit = right.unit)
        }

        fun orB(left: Correctness, right: Correctness): Correctness {
            if (!left.dissatisfiable) throw MiniscriptError.LeftNotDissatisfiable
            if (!right.dissatisfiable) throw MiniscriptError.RightNotDissatisfiable

            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.B, Base.W) -> Base.B
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = when (Pair(left.input, right.input)) {
                Pair(Input.Zero, Input.Zero) -> Input.Zero
                Pair(Input.Zero, Input.One), Pair(Input.One, Input.Zero) -> Input.One
                Pair(Input.Zero, Input.OneNonZero), Pair(Input.OneNonZero, Input.Zero) -> Input.One
                else -> Input.Any
            }
            return Correctness(newBase, newInput, dissatisfiable = true, unit = true)
        }

        fun orD(left: Correctness, right: Correctness): Correctness {
            if (!left.dissatisfiable) throw MiniscriptError.LeftNotDissatisfiable
            if (!left.unit) throw MiniscriptError.LeftNotUnit

            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.B, Base.B) -> Base.B
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = when (Pair(left.input, right.input)) {
                Pair(Input.Zero, Input.Zero) -> Input.Zero
                Pair(Input.One, Input.Zero), Pair(Input.OneNonZero, Input.Zero) -> Input.One
                else -> Input.Any
            }
            return Correctness(newBase, newInput, right.dissatisfiable, right.unit)
        }

        fun orC(left: Correctness, right: Correctness): Correctness {
            if (!left.dissatisfiable) throw MiniscriptError.LeftNotDissatisfiable
            if (!left.unit) throw MiniscriptError.LeftNotUnit

            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.B, Base.V) -> Base.V
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = when (Pair(left.input, right.input)) {
                Pair(Input.Zero, Input.Zero) -> Input.Zero
                Pair(Input.One, Input.Zero), Pair(Input.OneNonZero, Input.Zero) -> Input.One
                else -> Input.Any
            }
            return Correctness(newBase, newInput, dissatisfiable = false, unit = false)
        }

        fun orI(left: Correctness, right: Correctness): Correctness {
            val newBase = when (Pair(left.base, right.base)) {
                Pair(Base.B, Base.B) -> Base.B
                Pair(Base.V, Base.V) -> Base.V
                Pair(Base.K, Base.K) -> Base.K
                else -> throw MiniscriptError.ChildBase2(left.base, right.base)
            }
            val newInput = when (Pair(left.input, right.input)) {
                Pair(Input.Zero, Input.Zero) -> Input.One
                else -> Input.Any
            }
            return Correctness(newBase, newInput, left.dissatisfiable || right.dissatisfiable, left.unit && right.unit)
        }

        fun andOr(a: Correctness, b: Correctness, c: Correctness): Correctness {
            if (!a.dissatisfiable) throw MiniscriptError.LeftNotDissatisfiable
            if (!a.unit) throw MiniscriptError.LeftNotUnit

            val newBase = when (Triple(a.base, b.base, c.base)) {
                Triple(Base.B, Base.B, Base.B) -> Base.B
                Triple(Base.B, Base.K, Base.K) -> Base.K
                Triple(Base.B, Base.V, Base.V) -> Base.V
                else -> throw MiniscriptError.ChildBase3(a.base, b.base, c.base)
            }
            val newInput = when (Triple(a.input, b.input, c.input)) {
                Triple(Input.Zero, Input.Zero, Input.Zero) -> Input.Zero
                Triple(Input.Zero, Input.One, Input.One),
                Triple(Input.Zero, Input.One, Input.OneNonZero),
                Triple(Input.Zero, Input.OneNonZero, Input.One),
                Triple(Input.Zero, Input.OneNonZero, Input.OneNonZero),
                Triple(Input.One, Input.Zero, Input.Zero),
                Triple(Input.OneNonZero, Input.Zero, Input.Zero) -> Input.One
                else -> Input.Any
            }
            return Correctness(newBase, newInput, c.dissatisfiable, b.unit && c.unit)
        }

        fun threshold(k: Int, subs: List<Correctness>): Correctness {
            var numArgs = 0
            subs.forEachIndexed { i, subtype ->
                numArgs += when (subtype.input) {
                    Input.Zero -> 0
                    Input.One, Input.OneNonZero -> 1
                    Input.Any, Input.AnyNonZero -> 2
                }
                if (i == 0 && subtype.base != Base.B) throw MiniscriptError.ThresholdBase(i, subtype.base)
                if (i != 0 && subtype.base != Base.W) throw MiniscriptError.ThresholdBase(i, subtype.base)
                if (!subtype.unit) throw MiniscriptError.ThresholdNonUnit(i)
                if (!subtype.dissatisfiable) throw MiniscriptError.ThresholdDissat(i)
            }
            
            val input = when (numArgs) {
                0 -> Input.Zero
                1 -> Input.One
                else -> Input.Any
            }
            return Correctness(Base.B, input, dissatisfiable = true, unit = true)
        }

        private fun matchInputs(left: Input, right: Input): Input {
             return when (Pair(left, right)) {
                Pair(Input.Zero, Input.Zero) -> Input.Zero
                Pair(Input.Zero, Input.One), Pair(Input.One, Input.Zero) -> Input.One
                Pair(Input.Zero, Input.OneNonZero), Pair(Input.OneNonZero, Input.Zero) -> Input.OneNonZero
                Pair(Input.OneNonZero, Input.Any), Pair(Input.OneNonZero, Input.AnyNonZero),
                Pair(Input.OneNonZero, Input.One), Pair(Input.OneNonZero, Input.OneNonZero), // Covers OneNonZero as first
                Pair(Input.AnyNonZero, Input.Any), Pair(Input.AnyNonZero, Input.AnyNonZero),
                Pair(Input.AnyNonZero, Input.One), Pair(Input.AnyNonZero, Input.OneNonZero),
                Pair(Input.Zero, Input.AnyNonZero) -> Input.AnyNonZero
                
                // Fallback for logic in Rust:
                // (Input::OneNonZero, _) | (Input::AnyNonZero, _) | (Input::Zero, Input::AnyNonZero) => Input::AnyNonZero
                // The above specific matches cover some, let's just implement the logic directly
                 else -> {
                     if (left == Input.OneNonZero || left == Input.AnyNonZero || (left == Input.Zero && right == Input.AnyNonZero)) {
                         Input.AnyNonZero
                     } else {
                         Input.Any
                     }
                 }
            }
        }
    }
}
