package io.github.iml1s.miniscript

import kotlin.jvm.JvmInline

@JvmInline
value class AbsLockTime(val value: UInt) {
    fun toConsensusU32(): UInt = value
    fun isBlockHeight(): Boolean = value < LOCKTIME_THRESHOLD
    fun isBlockTime(): Boolean = value >= LOCKTIME_THRESHOLD

    companion object {
        private val LOCKTIME_THRESHOLD = 500_000_000u
    }
}

@JvmInline
value class RelLockTime(val value: UInt) {
    fun toConsensusU32(): UInt = value
    fun isHeightLocked(): Boolean = (value and SEQUENCE_LOCKTIME_TYPE_FLAG) == 0u
    fun isTimeLocked(): Boolean = (value and SEQUENCE_LOCKTIME_TYPE_FLAG) != 0u

    companion object {
        private val SEQUENCE_LOCKTIME_TYPE_FLAG = (1u shl 22)
    }
}
