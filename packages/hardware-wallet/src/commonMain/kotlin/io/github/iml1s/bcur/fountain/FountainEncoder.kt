package io.github.iml1s.bcur.fountain

import io.github.iml1s.bcur.CRC32

/**
 * Fountain Encoder for Multipart UR (MUR).
 * 
 * Generates a sequence of parts where:
 * - Parts 1 to seqLen are "pure" fragments (not mixed)
 * - Parts seqLen+1 and beyond are "mixed" fragments using XOR
 * 
 * Ported from https://github.com/sparrowwallet/hummingbird
 */
class FountainEncoder(
    message: ByteArray,
    private val maxFragmentLen: Int,
    private val minFragmentLen: Int = 10,
    firstSeqNum: Long = 0
) {
    val messageLen: Int = message.size
    val checksum: Long = CRC32.compute(message)
    val fragmentLen: Int
    val fragments: List<ByteArray>
    val seqLen: Int
    
    var seqNum: Long = firstSeqNum
        private set
    var partIndexes: List<Int> = emptyList()
        private set
    
    init {
        fragmentLen = findNominalFragmentLength(messageLen, minFragmentLen, maxFragmentLen)
        fragments = partitionMessage(message, fragmentLen)
        seqLen = fragments.size
    }
    
    /**
     * Generate the next part.
     */
    fun nextPart(): Part {
        seqNum += 1
        partIndexes = FountainUtils.chooseFragments(seqNum, seqLen, checksum)
        val mixed = mix(partIndexes)
        return Part(seqNum, seqLen, messageLen, checksum, mixed)
    }
    
    /**
     * Mix fragments using XOR.
     */
    private fun mix(partIndexes: List<Int>): ByteArray {
        var result = ByteArray(fragmentLen)
        for (index in partIndexes) {
            result = xor(fragments[index], result)
        }
        return result
    }
    
    /**
     * Check if all pure parts have been generated.
     */
    fun isComplete(): Boolean = seqNum >= seqLen
    
    /**
     * Check if message fits in a single part.
     */
    fun isSinglePart(): Boolean = seqLen == 1
    
    companion object {
        fun xor(a: ByteArray, b: ByteArray): ByteArray {
            val result = ByteArray(a.size)
            for (i in result.indices) {
                result[i] = (a[i].toInt() xor b[i].toInt()).toByte()
            }
            return result
        }
        
        fun partitionMessage(message: ByteArray, fragmentLen: Int): List<ByteArray> {
            val fragmentCount = (message.size + fragmentLen - 1) / fragmentLen
            val fragments = mutableListOf<ByteArray>()
            
            var start = 0
            for (i in 0 until fragmentCount) {
                val fragment = ByteArray(fragmentLen)
                val end = minOf(start + fragmentLen, message.size)
                message.copyInto(fragment, 0, start, end)
                fragments.add(fragment)
                start += fragmentLen
            }
            
            return fragments
        }
        
        fun findNominalFragmentLength(messageLen: Int, minFragmentLen: Int, maxFragmentLen: Int): Int {
            val maxFragmentCount = maxOf(1, messageLen / minFragmentLen)
            var fragmentLen = 0
            
            for (fragmentCount in 1..maxFragmentCount) {
                fragmentLen = (messageLen + fragmentCount - 1) / fragmentCount
                if (fragmentLen <= maxFragmentLen) {
                    break
                }
            }
            
            return fragmentLen
        }
    }
    
    /**
     * Represents a single fountain-encoded part.
     */
    data class Part(
        val seqNum: Long,
        val seqLen: Int,
        val messageLen: Int,
        val checksum: Long,
        val data: ByteArray
    ) {
        /**
         * Encode part as CBOR bytes.
         * Simple CBOR array: [seqNum, seqLen, messageLen, checksum, data]
         */
        fun toCborBytes(): ByteArray {
            // Simplified CBOR encoding (array of 5 elements)
            val result = mutableListOf<Byte>()
            
            // CBOR array header (5 elements)
            result.add(0x85.toByte())
            
            // seqNum as unsigned integer
            result.addAll(encodeUnsignedInt(seqNum.toULong()))
            
            // seqLen as unsigned integer
            result.addAll(encodeUnsignedInt(seqLen.toULong()))
            
            // messageLen as unsigned integer
            result.addAll(encodeUnsignedInt(messageLen.toULong()))
            
            // checksum as unsigned integer
            result.addAll(encodeUnsignedInt(checksum.toULong()))
            
            // data as byte string
            result.addAll(encodeByteString(data))
            
            return result.toByteArray()
        }
        
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            
            other as Part
            return seqNum == other.seqNum &&
                   seqLen == other.seqLen &&
                   messageLen == other.messageLen &&
                   checksum == other.checksum &&
                   data.contentEquals(other.data)
        }
        
        override fun hashCode(): Int {
            var result = seqNum.hashCode()
            result = 31 * result + seqLen
            result = 31 * result + messageLen
            result = 31 * result + checksum.hashCode()
            result = 31 * result + data.contentHashCode()
            return result
        }
        
        companion object {
            private fun encodeUnsignedInt(value: ULong): List<Byte> {
                return when {
                    value <= 23UL -> listOf(value.toByte())
                    value <= 0xFFUL -> listOf(0x18.toByte(), value.toByte())
                    value <= 0xFFFFUL -> listOf(
                        0x19.toByte(),
                        (value shr 8).toByte(),
                        value.toByte()
                    )
                    value <= 0xFFFFFFFFUL -> listOf(
                        0x1A.toByte(),
                        (value shr 24).toByte(),
                        (value shr 16).toByte(),
                        (value shr 8).toByte(),
                        value.toByte()
                    )
                    else -> listOf(
                        0x1B.toByte(),
                        (value shr 56).toByte(),
                        (value shr 48).toByte(),
                        (value shr 40).toByte(),
                        (value shr 32).toByte(),
                        (value shr 24).toByte(),
                        (value shr 16).toByte(),
                        (value shr 8).toByte(),
                        value.toByte()
                    )
                }
            }
            
            private fun encodeByteString(data: ByteArray): List<Byte> {
                val result = mutableListOf<Byte>()
                val len = data.size.toULong()
                
                when {
                    len <= 23UL -> result.add((0x40 + len.toInt()).toByte())
                    len <= 0xFFUL -> {
                        result.add(0x58.toByte())
                        result.add(len.toByte())
                    }
                    len <= 0xFFFFUL -> {
                        result.add(0x59.toByte())
                        result.add((len shr 8).toByte())
                        result.add(len.toByte())
                    }
                    else -> {
                        result.add(0x5A.toByte())
                        result.add((len shr 24).toByte())
                        result.add((len shr 16).toByte())
                        result.add((len shr 8).toByte())
                        result.add(len.toByte())
                    }
                }
                
                result.addAll(data.toList())
                return result
            }
        }
    }
}
