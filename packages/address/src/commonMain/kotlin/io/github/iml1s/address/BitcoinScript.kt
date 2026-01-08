package io.github.iml1s.address

/**
 * Bitcoin Script 工具類
 * 
 * 用於將 Bitcoin 地址解碼為 scriptPubKey (鎖定腳本)
 */
object BitcoinScript {

    /**
     * 將 Bitcoin 地址轉換為 scriptPubKey
     * 
     * 支援的地址格式：
     * - P2PKH (1... 開頭)
     * - P2SH (3... 開頭)  
     * - P2WPKH/P2WSH (bc1q... 開頭)
     * - P2TR Taproot (bc1p... 開頭)
     * - Testnet 地址 (m/n/2/tb1...)
     *
     * @param address Bitcoin 地址字串
     * @return scriptPubKey 位元組陣列
     * @throws IllegalArgumentException 如果地址格式無效或不支援
     */
    fun addressToScriptPubKey(address: String): ByteArray {
        // 嘗試 Bech32 (SegWit) 解碼
        val bech32Data = Bech32.decodeSegwitAddress(address)
        if (bech32Data != null) {
            val (version, program) = bech32Data
            return when (version) {
                0 -> {
                    // P2WPKH (20 bytes) 或 P2WSH (32 bytes)
                    // OP_0 <len> <program>
                    byteArrayOf(0x00, program.size.toByte()) + program
                }
                1 -> {
                    // Taproot (P2TR)
                    // OP_1 (0x51) <len> <program>
                    byteArrayOf(0x51.toByte(), program.size.toByte()) + program
                }
                else -> throw IllegalArgumentException("不支援的 SegWit 版本: $version")
            }
        }

        // 嘗試 Base58 (Legacy/P2SH) 解碼
        val base58Data = Base58.decodeCheck(address)
        if (base58Data != null) {
            val (version, payload) = base58Data
            val vInt = version.toInt() and 0xFF
            
            // Mainnet P2PKH (0x00) 或 Testnet P2PKH (0x6F = 111)
            if (vInt == 0x00 || vInt == 0x6F) {
                // OP_DUP OP_HASH160 <len> <hash> OP_EQUALVERIFY OP_CHECKSIG
                return byteArrayOf(
                    0x76.toByte(), // OP_DUP
                    0xA9.toByte(), // OP_HASH160
                    0x14.toByte()  // 20 bytes
                ) + payload + byteArrayOf(
                    0x88.toByte(), // OP_EQUALVERIFY
                    0xAC.toByte()  // OP_CHECKSIG
                )
            }
            
            // Mainnet P2SH (0x05) 或 Testnet P2SH (0xC4 = 196)
            if (vInt == 0x05 || vInt == 0xC4) {
                // OP_HASH160 <len> <hash> OP_EQUAL
                return byteArrayOf(
                    0xA9.toByte(), // OP_HASH160
                    0x14.toByte()  // 20 bytes
                ) + payload + byteArrayOf(
                    0x87.toByte()  // OP_EQUAL
                )
            }
        }

        throw IllegalArgumentException("無效或不支援的 Bitcoin 地址: $address")
    }

    /**
     * 計算 Electrum 協定所需的 scriptHash
     * 
     * scriptHash = SHA256(scriptPubKey) 的位元組反轉後十六進位編碼
     *
     * @param address Bitcoin 地址
     * @return scriptHash (64 字元十六進位字串)
     */
    fun addressToScriptHash(address: String): String {
        val scriptPubKey = addressToScriptPubKey(address)
        val hash = io.github.iml1s.crypto.Secp256k1Pure.sha256(scriptPubKey)
        return io.github.iml1s.crypto.Hex.encode(hash.reversedArray())
    }
}
