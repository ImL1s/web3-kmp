package io.github.iml1s.crypto

object Blake2b {
    private val IV = longArrayOf(
        0x6a09e667f3bcc908UL.toLong(), 0xbb67ae8584caa73bUL.toLong(),
        0x3c6ef372fe94f82bUL.toLong(), 0xa54ff53a5f1d36f1UL.toLong(),
        0x510e527fade682d1UL.toLong(), 0x9b05688c2b3e6c1fUL.toLong(),
        0x1f83d9abfb41bd6bUL.toLong(), 0x5be0cd19137e2179UL.toLong()
    )

    private val SIGMA = arrayOf(
        byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        byteArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        byteArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        byteArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        byteArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        byteArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        byteArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        byteArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        byteArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        byteArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
    )

    fun hash512(data: ByteArray): ByteArray = digest(data, digestSize = 64)
    fun hash224(data: ByteArray): ByteArray = digest(data, digestSize = 28)

    fun digest(
        data: ByteArray,
        key: ByteArray? = null,
        salt: ByteArray? = null,
        personalization: ByteArray? = null,
        digestSize: Int = 64
    ): ByteArray {
        require(digestSize in 1..64)
        require(key == null || key.size <= 64)
        require(salt == null || salt.size <= 16)
        require(personalization == null || personalization.size <= 16)

        // Initialize State
        val chainValue = IV.copyOf()
        val keyLen = key?.size ?: 0
        chainValue[0] = chainValue[0] xor (0x01010000L or (keyLen.toLong() shl 8) or digestSize.toLong())

        if (salt != null) {
            val s = ByteArray(16)
            salt.copyInto(s)
            chainValue[4] = chainValue[4] xor bytesToLong(s, 0)
            chainValue[5] = chainValue[5] xor bytesToLong(s, 8)
        }

        if (personalization != null) {
            val p = ByteArray(16)
            personalization.copyInto(p)
            chainValue[6] = chainValue[6] xor bytesToLong(p, 0)
            chainValue[7] = chainValue[7] xor bytesToLong(p, 8)
        }

        val buffer = ByteArray(128)
        var bufferPos = 0
        var totalBytes = 0L

        // Process Key Block
        if (keyLen > 0) {
            key!!.copyInto(buffer, 0, 0, keyLen)
            // Pad rest with zeros (buffer starts zeroed)
            
            // If data is empty, key block is the last block
            if (data.isEmpty()) {
                compress(chainValue, buffer, 128, true)
                return output(chainValue, digestSize)
            }
            
            // Otherwise, compress key block (not last)
            compress(chainValue, buffer, 128, false)
            totalBytes = 128
            bufferPos = 0
            buffer.fill(0)
        }

        // Process Data
        // Correct buffering logic:
        var offset = 0
        var remaining = data.size
        
        // Special case: empty data and no key.
        if (remaining == 0 && keyLen == 0) {
             compress(chainValue, buffer, 0, true)
             return output(chainValue, digestSize)
        }

        while (remaining > 0) {
            if (bufferPos == 128) {
                totalBytes += 128
                compress(chainValue, buffer, totalBytes, false)
                bufferPos = 0
                buffer.fill(0) // Safe clear
            }
            val copyAmt = minOf(remaining, 128 - bufferPos)
            data.copyInto(buffer, bufferPos, offset, offset + copyAmt)
            bufferPos += copyAmt
            remaining -= copyAmt
            offset += copyAmt
        }

        // Final Block
        totalBytes += bufferPos
        // Pad with zeros (already zero if simple copy, but ensure last part is zero)
        for (i in bufferPos until 128) buffer[i] = 0
        compress(chainValue, buffer, totalBytes, true)

        return output(chainValue, digestSize)
    }

    private fun output(chainValue: LongArray, digestSize: Int): ByteArray {
        val out = ByteArray(digestSize)
        for (i in 0 until digestSize) {
            out[i] = (chainValue[i / 8] ushr (8 * (i % 8))).toByte()
        }
        return out
    }

    private fun compress(h: LongArray, chunk: ByteArray, t: Long, isLast: Boolean) {
        val v = LongArray(16)
        val m = LongArray(16)

        // Load V
        for (i in 0..7) {
            v[i] = h[i]
            v[i + 8] = IV[i]
        }

        v[12] = v[12] xor t
        v[13] = v[13] xor 0 // t high 64
        if (isLast) {
            v[14] = v[14] xor -1L
        }

        // Load M
        for (i in 0..15) {
            m[i] = bytesToLong(chunk, i * 8)
        }

        // Rounds
        for (i in 0..11) {
            val s = SIGMA[i]
            // Unroll G
            G(v, 0, 4, 8, 12, m[s[0].toInt()], m[s[1].toInt()])
            G(v, 1, 5, 9, 13, m[s[2].toInt()], m[s[3].toInt()])
            G(v, 2, 6, 10, 14, m[s[4].toInt()], m[s[5].toInt()])
            G(v, 3, 7, 11, 15, m[s[6].toInt()], m[s[7].toInt()])
            G(v, 0, 5, 10, 15, m[s[8].toInt()], m[s[9].toInt()])
            G(v, 1, 6, 11, 12, m[s[10].toInt()], m[s[11].toInt()])
            G(v, 2, 7, 8, 13, m[s[12].toInt()], m[s[13].toInt()])
            G(v, 3, 4, 9, 14, m[s[14].toInt()], m[s[15].toInt()])
        }

        // Update H
        for (i in 0..7) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun G(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = rotr64(v[d] xor v[a], 32)
        v[c] = v[c] + v[d]
        v[b] = rotr64(v[b] xor v[c], 24)
        v[a] = v[a] + v[b] + y
        v[d] = rotr64(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = rotr64(v[b] xor v[c], 63)
    }

    private fun rotr64(x: Long, n: Int): Long {
        return (x ushr n) or (x shl (64 - n))
    }

    private fun bytesToLong(b: ByteArray, off: Int): Long {
        return (b[off].toLong() and 0xffL) or
                ((b[off + 1].toLong() and 0xffL) shl 8) or
                ((b[off + 2].toLong() and 0xffL) shl 16) or
                ((b[off + 3].toLong() and 0xffL) shl 24) or
                ((b[off + 4].toLong() and 0xffL) shl 32) or
                ((b[off + 5].toLong() and 0xffL) shl 40) or
                ((b[off + 6].toLong() and 0xffL) shl 48) or
                ((b[off + 7].toLong() and 0xffL) shl 56)
    }
}
