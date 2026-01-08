package io.github.iml1s.crypto

/**
 * CRC16-CCITT 校驗和計算
 *
 * 用於 TON 地址的校驗和生成。
 *
 * 規格：
 * - 多項式: 0x1021 (x^16 + x^12 + x^5 + 1)
 * - 初始值: 0x0000
 * - 輸入/輸出反轉: 無
 * - 最終異或: 0x0000
 *
 * @see <a href="https://docs.ton.org/learn/overviews/addresses">TON Address Format</a>
 */
object Crc16 {

    private const val POLYNOMIAL = 0x1021
    private const val INITIAL_VALUE = 0x0000

    /**
     * 計算 CRC16-CCITT 校驗和
     *
     * @param data 要計算校驗和的數據
     * @return 2 字節的校驗和（大端序）
     */
    fun ccitt(data: ByteArray): ByteArray {
        var crc = INITIAL_VALUE

        for (byte in data) {
            crc = crc xor ((byte.toInt() and 0xFF) shl 8)
            repeat(8) {
                crc = if ((crc and 0x8000) != 0) {
                    (crc shl 1) xor POLYNOMIAL
                } else {
                    crc shl 1
                }
                crc = crc and 0xFFFF // Keep it 16-bit
            }
        }

        return byteArrayOf(
            ((crc shr 8) and 0xFF).toByte(),
            (crc and 0xFF).toByte()
        )
    }
}
