package io.github.iml1s.crypto

/**
 * Base58 編碼/解碼實現
 * 用於 Solana 地址和交易簽名的編碼
 */
object Base58 {
    const val BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    // pre-computed indexes for standard alphabet
    private val BTC_INDEXES = IntArray(128) { -1 }

    init {
        for (i in BTC_ALPHABET.indices) {
            BTC_INDEXES[BTC_ALPHABET[i].code] = i
        }
    }

    /**
     * Encode to Base58 using specified alphabet
     */
    fun encode(input: ByteArray, alphabet: String = BTC_ALPHABET): String {
        if (input.isEmpty()) return ""

        // 🔧 Fix: copy input to avoid modification
        val inputCopy = input.copyOf()

        // Count leading zeros
        var zeroCount = 0
        while (zeroCount < inputCopy.size && inputCopy[zeroCount].toInt() == 0) {
            ++zeroCount
        }

        // Convert to base 58
        val temp = ByteArray(inputCopy.size * 2)
        var j = temp.size

        var startAt = zeroCount
        while (startAt < inputCopy.size) {
            val mod = divmod(inputCopy, startAt, 256, 58)
            if (inputCopy[startAt].toInt() == 0) {
                ++startAt
            }
            temp[--j] = alphabet[mod.toInt()].code.toByte()
        }

        // Skip leading zeros
        while (j < temp.size && temp[j].toInt() == alphabet[0].code) {
            ++j
        }

        // Add leading zeros ('1' in standard alphabet)
        while (--zeroCount >= 0) {
            temp[--j] = alphabet[0].code.toByte()
        }

        val output = temp.copyOfRange(j, temp.size)
        return output.decodeToString()
    }

    /**
     * Base58Check Encode (Checksum)
     */
    fun encodeWithChecksum(input: ByteArray, alphabet: String = BTC_ALPHABET): String {
        val hash = sha256(sha256(input))
        val checksum = hash.copyOfRange(0, 4)
        val dataWithChecksum = input + checksum
        return encode(dataWithChecksum, alphabet)
    }

    private fun sha256(data: ByteArray): ByteArray {
        return Secp256k1Pure.sha256(data)
    }

    /**
     * Decode Base58 string
     */
    fun decode(input: String, alphabet: String = BTC_ALPHABET): ByteArray {
        if (input.isEmpty()) return ByteArray(0)

        // Use cached indexes for default alphabet, or build temporary map
        val indexes = if (alphabet === BTC_ALPHABET) BTC_INDEXES else buildIndexes(alphabet)

        // Check character validity
        val input58 = ByteArray(input.length)
        for (i in input.indices) {
            val c = input[i]
            val code = c.code
            var digit = -1
             if (code < 128) {
                 digit = indexes[code]
             }
            if (digit < 0) {
                throw IllegalArgumentException("Invalid Base58 character: $c")
            }
            input58[i] = digit.toByte()
        }

        // Count leading zeros
        var zeroCount = 0
        while (zeroCount < input58.size && input58[zeroCount].toInt() == 0) {
            ++zeroCount
        }

        // Convert to base 256
        val temp = ByteArray(input.length)
        var j = temp.size

        var startAt = zeroCount
        while (startAt < input58.size) {
            val mod = divmod(input58, startAt, 58, 256)
            if (input58[startAt].toInt() == 0) {
                ++startAt
            }
            temp[--j] = mod
        }

        // Skip leading zeros
        while (j < temp.size && temp[j].toInt() == 0) {
            ++j
        }

        return ByteArray(zeroCount + (temp.size - j)).apply {
            temp.copyInto(this, zeroCount, j, temp.size)
        }
    }

    private fun buildIndexes(alphabet: String): IntArray {
        val indexes = IntArray(128) { -1 }
        for (i in alphabet.indices) {
            val code = alphabet[i].code
            if (code < 128) {
                indexes[code] = i
            }
        }
        return indexes
    }

    /**
     * DivMod logic
     */
    private fun divmod(number: ByteArray, startAt: Int, base: Int, divisor: Int): Byte {
        var remainder = 0
        for (i in startAt until number.size) {
            val digit = number[i].toInt() and 0xFF
            val temp = remainder * base + digit
            number[i] = (temp / divisor).toByte()
            remainder = temp % divisor
        }
        return remainder.toByte()
    }
}
