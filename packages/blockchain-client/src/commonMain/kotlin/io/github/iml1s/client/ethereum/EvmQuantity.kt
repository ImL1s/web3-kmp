package io.github.iml1s.client.ethereum

/**
 * Unsigned hex quantity codec for Ethereum JSON-RPC (uint256).
 */
object EvmQuantity {
    fun hexToDecimal(hex: String): String {
        val h = hex.trim().removePrefix("0x").removePrefix("0X").lowercase().ifEmpty { "0" }
        require(h.all { it in '0'..'9' || it in 'a'..'f' }) { "Invalid hex quantity" }
        require(h.length <= 64) { "Quantity exceeds uint256" }
        var dec = "0"
        for (ch in h) {
            val digit = if (ch <= '9') ch - '0' else ch - 'a' + 10
            dec = mulAdd(dec, 16, digit)
        }
        return dec
    }

    private fun mulAdd(dec: String, mul: Int, add: Int): String {
        val digits = dec.map { it - '0' }.toMutableList()
        var carry = add
        for (i in digits.indices.reversed()) {
            val v = digits[i] * mul + carry
            digits[i] = v % 10
            carry = v / 10
        }
        val prefix = ArrayList<Int>()
        while (carry > 0) {
            prefix.add(0, carry % 10)
            carry /= 10
        }
        return (prefix + digits).joinToString("").trimStart('0').ifEmpty { "0" }
    }
}
