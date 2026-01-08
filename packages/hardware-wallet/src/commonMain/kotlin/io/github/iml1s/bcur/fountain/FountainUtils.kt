package io.github.iml1s.bcur.fountain

/**
 * Fountain Code utilities for Multipart UR (MUR).
 * 
 * Fountain Codes enable rateless encoding where encoder and decoder
 * use the same deterministic random sequence to select fragments.
 * 
 * Ported from https://github.com/sparrowwallet/hummingbird
 */
object FountainUtils {
    
    /**
     * Choose which fragments to mix for a given sequence number.
     * 
     * - For seqNum <= seqLen: returns single pure fragment (index = seqNum - 1)
     * - For seqNum > seqLen: returns mixed fragments using Xoshiro256** RNG
     */
    fun chooseFragments(seqNum: Long, seqLen: Int, checksum: Long): List<Int> {
        if (seqNum <= seqLen) {
            return listOf((seqNum - 1).toInt())
        } else {
            // Create seed from seqNum and checksum
            val seed = ByteArray(8)
            seed[0] = ((seqNum shr 24) and 0xFF).toByte()
            seed[1] = ((seqNum shr 16) and 0xFF).toByte()
            seed[2] = ((seqNum shr 8) and 0xFF).toByte()
            seed[3] = (seqNum and 0xFF).toByte()
            seed[4] = ((checksum shr 24) and 0xFF).toByte()
            seed[5] = ((checksum shr 16) and 0xFF).toByte()
            seed[6] = ((checksum shr 8) and 0xFF).toByte()
            seed[7] = (checksum and 0xFF).toByte()
            
            val rng = Xoshiro256StarStar(seed)
            val degree = chooseDegree(seqLen, rng)
            val indexes = (0 until seqLen).toMutableList()
            val shuffled = shuffled(indexes, rng)
            return shuffled.take(degree)
        }
    }
    
    /**
     * Choose the degree (number of fragments to mix) using probability distribution.
     * The probability of degree i is 1/i (favors smaller degrees).
     */
    private fun chooseDegree(seqLen: Int, rng: Xoshiro256StarStar): Int {
        val probabilities = (1..seqLen).map { 1.0 / it }
        val sampler = RandomSampler(probabilities)
        return sampler.next(rng) + 1
    }
    
    /**
     * Fisher-Yates shuffle using deterministic RNG.
     */
    private fun shuffled(indexes: MutableList<Int>, rng: Xoshiro256StarStar): List<Int> {
        val remaining = indexes.toMutableList()
        val result = mutableListOf<Int>()
        
        while (remaining.isNotEmpty()) {
            val index = rng.nextInt(0, remaining.size)
            result.add(remaining.removeAt(index))
        }
        
        return result
    }
}

/**
 * Alias sampling for weighted random selection.
 * Used to select degree with probability 1/degree.
 */
class RandomSampler(probabilities: List<Double>) {
    private val aliases: IntArray
    private val probs: DoubleArray
    private val n: Int = probabilities.size
    
    init {
        val sum = probabilities.sum()
        val normalizedProbs = probabilities.map { it / sum * n }
        
        aliases = IntArray(n)
        probs = DoubleArray(n)
        
        val small = mutableListOf<Int>()
        val large = mutableListOf<Int>()
        
        for (i in 0 until n) {
            if (normalizedProbs[i] < 1.0) {
                small.add(i)
            } else {
                large.add(i)
            }
        }
        
        val probsCopy = normalizedProbs.toMutableList()
        
        while (small.isNotEmpty() && large.isNotEmpty()) {
            val l = small.removeAt(small.size - 1)
            val g = large.removeAt(large.size - 1)
            
            probs[l] = probsCopy[l]
            aliases[l] = g
            
            probsCopy[g] = (probsCopy[g] + probsCopy[l]) - 1.0
            
            if (probsCopy[g] < 1.0) {
                small.add(g)
            } else {
                large.add(g)
            }
        }
        
        while (large.isNotEmpty()) {
            probs[large.removeAt(large.size - 1)] = 1.0
        }
        
        while (small.isNotEmpty()) {
            probs[small.removeAt(small.size - 1)] = 1.0
        }
    }
    
    fun next(rng: Xoshiro256StarStar): Int {
        val i = rng.nextInt(n)
        return if (rng.nextDouble() < probs[i]) i else aliases[i]
    }
}
