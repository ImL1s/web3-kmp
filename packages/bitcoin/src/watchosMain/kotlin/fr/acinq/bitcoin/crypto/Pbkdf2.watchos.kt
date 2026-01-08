package fr.acinq.bitcoin.crypto

/**
 * Pure Kotlin PBKDF2-HMAC-SHA512 implementation for watchOS.
 * This avoids cinterop bit-width issues between 32-bit and 64-bit watchOS targets.
 */
public actual object Pbkdf2 {

    public actual fun withHmacSha512(password: ByteArray, salt: ByteArray, count: Int, dkLen: Int): ByteArray {
        return pbkdf2HmacSha512(password, salt, count, dkLen)
    }

    private fun pbkdf2HmacSha512(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int): ByteArray {
        val hLen = 64 // SHA-512 produces 64 bytes
        val dkBlocks = (dkLen + hLen - 1) / hLen
        val dk = ByteArray(dkLen)

        for (i in 1..dkBlocks) {
            val block = f(password, salt, iterations, i)
            val offset = (i - 1) * hLen
            val copyLen = minOf(hLen, dkLen - offset)
            block.copyInto(dk, offset, 0, copyLen)
        }

        return dk
    }

    private fun f(password: ByteArray, salt: ByteArray, iterations: Int, blockIndex: Int): ByteArray {
        // U1 = PRF(Password, Salt || INT_32_BE(i))
        val intBe = byteArrayOf(
            ((blockIndex shr 24) and 0xFF).toByte(),
            ((blockIndex shr 16) and 0xFF).toByte(),
            ((blockIndex shr 8) and 0xFF).toByte(),
            (blockIndex and 0xFF).toByte()
        )
        var u = hmacSha512(password, salt + intBe)
        var result = u.copyOf()

        // U2 ... Uc
        for (j in 2..iterations) {
            u = hmacSha512(password, u)
            for (k in result.indices) {
                result[k] = (result[k].toInt() xor u[k].toInt()).toByte()
            }
        }

        return result
    }

    private fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
        val blockSize = 128
        val opad = 0x5c.toByte()
        val ipad = 0x36.toByte()

        var k = if (key.size > blockSize) sha512(key) else key
        if (k.size < blockSize) k = k + ByteArray(blockSize - k.size)

        val oKeyPad = ByteArray(blockSize) { i -> (k[i].toInt() xor opad.toInt()).toByte() }
        val iKeyPad = ByteArray(blockSize) { i -> (k[i].toInt() xor ipad.toInt()).toByte() }

        return sha512(oKeyPad + sha512(iKeyPad + data))
    }

    private fun sha512(data: ByteArray): ByteArray {
        val digest = Sha512()
        digest.update(data, 0, data.size)
        val out = ByteArray(64)
        digest.doFinal(out, 0)
        return out
    }
}
