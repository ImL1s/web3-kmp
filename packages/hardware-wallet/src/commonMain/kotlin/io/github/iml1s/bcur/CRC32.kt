package io.github.iml1s.bcur

/**
 * Pure Kotlin CRC32 implementation for KMP (watchOS compatible).
 * Based on the standard CRC-32 polynomial (IEEE 802.3).
 */
object CRC32 {
    private val CRC_TABLE = IntArray(256)
    
    init {
        val polynomial = 0xEDB88320.toInt()
        for (i in 0 until 256) {
            var crc = i
            for (j in 0 until 8) {
                crc = if (crc and 1 != 0) {
                    (crc ushr 1) xor polynomial
                } else {
                    crc ushr 1
                }
            }
            CRC_TABLE[i] = crc
        }
    }
    
    fun compute(data: ByteArray): Long {
        var crc = 0xFFFFFFFF.toInt()
        for (byte in data) {
            val index = (crc xor byte.toInt()) and 0xFF
            crc = (crc ushr 8) xor CRC_TABLE[index]
        }
        return (crc xor 0xFFFFFFFF.toInt()).toLong() and 0xFFFFFFFFL
    }
    
    fun toBytes(crc: Long): ByteArray {
        return byteArrayOf(
            ((crc shr 24) and 0xFF).toByte(),
            ((crc shr 16) and 0xFF).toByte(),
            ((crc shr 8) and 0xFF).toByte(),
            (crc and 0xFF).toByte()
        )
    }
    
    fun fromBytes(bytes: ByteArray): Long {
        require(bytes.size >= 4) { "CRC32 requires 4 bytes" }
        return ((bytes[0].toLong() and 0xFF) shl 24) or
               ((bytes[1].toLong() and 0xFF) shl 16) or
               ((bytes[2].toLong() and 0xFF) shl 8) or
               (bytes[3].toLong() and 0xFF)
    }
}
