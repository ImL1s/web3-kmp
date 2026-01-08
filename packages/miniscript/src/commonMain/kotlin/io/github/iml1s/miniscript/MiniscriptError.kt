package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.types.Base

sealed class MiniscriptError(message: String) : Exception(message) {
    data class ChildBase1(val base: Base) : MiniscriptError("Child base error: $base")
    data class ChildBase2(val base1: Base, val base2: Base) : MiniscriptError("Child base error: $base1, $base2")
    data class ChildBase3(val base1: Base, val base2: Base, val base3: Base) : MiniscriptError("Child base error: $base1, $base2, $base3")
    data object SwapNonOne : MiniscriptError("Swap requires input 1 or 1nonzero")
    data object NonZeroDupIf : MiniscriptError("DupIf requires input 0")
    data object NonZeroZero : MiniscriptError("NonZero requires input 1nonzero or anynonzero")
    data object LeftNotDissatisfiable : MiniscriptError("Left branch not dissatisfiable")
    data object RightNotDissatisfiable : MiniscriptError("Right branch not dissatisfiable")
    data object LeftNotUnit : MiniscriptError("Left branch not unit")
    data class ThresholdBase(val index: Int, val base: Base) : MiniscriptError("Threshold base error at index $index: $base")
    data class ThresholdNonUnit(val index: Int) : MiniscriptError("Threshold non-unit error at index $index")
    data class ThresholdDissat(val index: Int) : MiniscriptError("Threshold dissat error at index $index")
}
