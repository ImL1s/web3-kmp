package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.MiniscriptError.ThresholdBase

data class Threshold<out T>(
    val k: Int,
    val data: List<T>,
    val max: Int = 0 // 0 means no limit, matching Rust const generic MAX
) {
    init {
        if (k == 0) throw IllegalArgumentException("Threshold k must be > 0")
        if (k > data.size) throw IllegalArgumentException("Threshold k must be <= n")
        if (max > 0 && data.size > max) throw IllegalArgumentException("Threshold n must be <= max ($max)")
    }

    fun n(): Int = data.size
    // fun data(): List<T> = data // Removed as it is now a property
    
    fun <U> map(transform: (T) -> U): Threshold<U> {
        return Threshold(k, data.map(transform), max)
    }

    /*
    fun <U> mapRef(transform: (T) -> U): Threshold<U> = map(transform)
    fun <U> translateRef(transform: (T) -> Result<U, Throwable>): Result<Threshold<U>, Throwable> {
        // ...
    }
    */
    
    companion object {
        fun <T> create(k: Int, inner: List<T>, max: Int = 0): Threshold<T> {
            return Threshold(k, inner, max)
        }
    }
}
