package io.github.iml1s.crypto

/**
 * Bech32 and Bech32m implementation
 *
 * References:
 * - BIP 173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 * - BIP 350: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
 */
object Bech32 {
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7lm"
    
    // Checksum constants
    const val BECH32_CONST = 1
    const val BECH32M_CONST = 0x2bc830a3
    
    /**
     * Decoded Bech32 data
     */
    data class Bech32Data(val hrp: String, val data: ByteArray, val spec: Spec)
    
    enum class Spec {
        BECH32, BECH32M
    }

    /**
     * Encode to Bech32/Bech32m string
     */
    fun encode(hrp: String, data: ByteArray, spec: Spec = Spec.BECH32): String {
        require(hrp.isNotEmpty()) { "Human-readable part must not be empty" }
        // data can be empty (e.g. for pure checksum tests)
        
        val checksumConstant = when (spec) {

            Spec.BECH32 -> BECH32_CONST
            Spec.BECH32M -> BECH32M_CONST
        }
        
        val checksum = createChecksum(hrp, data, checksumConstant)
        val combined = data + checksum
        
        val result = StringBuilder()
        result.append(hrp)
        result.append('1')
        for (b in combined) {
            result.append(CHARSET[b.toInt()])
        }
        return result.toString()
    }

    /**
     * Decode Bech32/Bech32m string
     */
    fun decode(bech32: String): Bech32Data {
        require(bech32.length <= 2000) { "Bech32 string too long" }
        
        // Check case
        var hasLower = false
        var hasUpper = false
        for (c in bech32) {
            if (c in 'a'..'z') hasLower = true
            if (c in 'A'..'Z') hasUpper = true
            require(c.code in 33..126) { "Invalid character: $c" }
        }
        require(!(hasLower && hasUpper)) { "Mixed case not allowed" }
        
        val input = bech32.lowercase()
        val pos = input.lastIndexOf('1')
        require(pos >= 1) { "Missing separator '1'" }
        require(pos + 7 <= input.length) { "Data too short" }
        
        val hrp = input.substring(0, pos)
        val data = ByteArray(input.length - 1 - pos)
        
        for (i in 0 until data.size) {
            val charIndex = CHARSET.indexOf(input[pos + 1 + i])
            require(charIndex != -1) { "Invalid data character: ${input[pos + 1 + i]}" }
            data[i] = charIndex.toByte()
        }
        
        val const = verifyChecksum(hrp, data)
        val spec = when (const) {
            BECH32_CONST -> Spec.BECH32
            BECH32M_CONST -> Spec.BECH32M
            else -> throw IllegalArgumentException("Invalid checksum: ${const.toString(16)}")
        }
        
        return Bech32Data(hrp, data.sliceArray(0 until data.size - 6), spec)
    }
    
    /**
     * Convert bits (e.g., 8-bit to 5-bit)
     */
    fun convertBits(
        data: ByteArray,
        fromBits: Int,
        toBits: Int,
        pad: Boolean
    ): ByteArray {
        var acc = 0
        var bits = 0
        val out = mutableListOf<Byte>()
        val maxv = (1 shl toBits) - 1
        val maxAcc = (1 shl (fromBits + toBits - 1)) - 1
        
        for (b in data) {
            val value = b.toInt() and 0xFF
            if ((value ushr fromBits) != 0) {
                throw IllegalArgumentException("Input value exceeds $fromBits bits")
            }
            acc = ((acc shl fromBits) or value) and maxAcc
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                out.add(((acc ushr bits) and maxv).toByte())
            }
        }
        
        if (pad) {
            if (bits > 0) {
                out.add(((acc shl (toBits - bits)) and maxv).toByte())
            }
        } else if (bits >= fromBits || ((acc shl (toBits - bits)) and maxv) != 0) {
            throw IllegalArgumentException("Invalid padding")
        }
        
        return out.toByteArray()
    }
    
    // Internal functions
    
    private fun polymod(values: ByteArray): Int {
        var chk = 1L
        for (v in values) {
            val top = chk shr 25
            chk = ((chk and 0x1ffffffL) shl 5) xor (v.toLong() and 0xffL)
            if ((top and 1L) != 0L) chk = chk xor 0x3b6a57b2L
            if ((top and 2L) != 0L) chk = chk xor 0x26508e6dL
            if ((top and 4L) != 0L) chk = chk xor 0x1ea119faL
            if ((top and 8L) != 0L) chk = chk xor 0x3d4233ddL
            if ((top and 16L) != 0L) chk = chk xor 0x2a1462b3L
        }
        return chk.toInt()
    }


    
    private fun expandHrp(hrp: String): ByteArray {
        val ret = ByteArray(hrp.length * 2 + 1)
        for (i in hrp.indices) {
            ret[i] = (hrp[i].code ushr 5).toByte()
            ret[i + hrp.length + 1] = (hrp[i].code and 31).toByte()
        }
        ret[hrp.length] = 0
        return ret
    }
    
    private fun verifyChecksum(hrp: String, data: ByteArray): Int {
        return polymod(expandHrp(hrp) + data)
    }
    
    private fun createChecksum(hrp: String, data: ByteArray, specConst: Int): ByteArray {
        val values = expandHrp(hrp) + data + ByteArray(6) // Append 6 zeros
        val mod = polymod(values) xor specConst
        
        val ret = ByteArray(6)
        for (i in 0 until 6) {
            ret[i] = ((mod ushr (5 * (5 - i))) and 31).toByte()
        }
        return ret
    }
}
