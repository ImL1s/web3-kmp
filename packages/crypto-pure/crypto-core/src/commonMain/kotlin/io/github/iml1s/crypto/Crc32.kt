package io.github.iml1s.crypto

/**
 * CRC32 Implementation (IEEE 802.3)
 * Polynomial: 0xEDB88320
 */
object Crc32 {
    private val TABLE = IntArray(256)

    init {
        for (i in 0 until 256) {
            var crc = i
            for (j in 0 until 8) {
                crc = if ((crc and 1) != 0) {
                    (crc ushr 1) xor 0xEDB88320.toInt()
                } else {
                    crc ushr 1
                }
            }
            TABLE[i] = crc
        }
    }

    /**
     * Compute CRC32 checksum of data.
     */
    fun compute(data: ByteArray): Int {
        var crc = -1 // 0xFFFFFFFF
        for (b in data) {
            val i = (crc xor b.toInt()) and 0xFF
            crc = (crc ushr 8) xor TABLE[i]
        }
        return crc.inv() // xor 0xFFFFFFFF
    }
}
