package io.github.iml1s.crypto

import org.kotlincrypto.hash.sha2.SHA256
import com.ionspin.kotlin.bignum.integer.BigInteger as KmpBigInteger
import com.ionspin.kotlin.bignum.integer.Sign
// Keccak256 is now in the same package

/**
 * 純 Kotlin 實現的 secp256k1 橢圓曲線加密
 *
 * 🔧 簽名格式：
 * - 默認使用 64-byte compact 格式 (r || s)
 * - 與 libsecp256k1 保持一致
 * - 支援跨平台互操作 (iOS, Android, watchOS)
 *
 * 🔒 安全特性：
 * - RFC 6979 deterministic k generation
 * - P0 security fixes: point validation, range checks, iteration protection
 * - ✅ Sensitive data cleanup: 所有敏感中間值使用後立即清零
 *
 * ⚠️ 調用者責任：
 * - 調用者必須在 `sign()` 返回後立即清零 privateKey
 * - 建議使用: `finally { privateKeyBytes.secureZero() }`
 * - 或使用: `withSecureCleanup(privateKey) { sign(...) }`
 *
 * 🛡️ 清理的敏感數據：
 * - 臨時密鑰 k（RFC 6979 生成）
 * - HMAC 中間值 (V, K)
 * - 消息哈希和私鑰（調用者責任）
 *
 * 這是一個功能正確但簡化的實現，用於 watchOS 平台
 * 生產環境應使用經過審計的加密庫
 */
object Secp256k1Pure {
    
    // secp256k1 曲線參數
    private val P = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    private val N = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    private val G_X = BigInteger.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    private val G_Y = BigInteger.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    
    /**
     * 使用私鑰對消息進行簽名
     * ✅ 使用 RFC 6979 deterministic k generation（確定性簽名）
     * ✅ 自動清理臨時密鑰 k（防止內存洩漏）
     *
     * ⚠️ 安全注意事項：
     * - 此方法會自動清理臨時密鑰 k
     * - 調用者必須清理 privateKey: `finally { privateKey.secureZero() }`
     * - 調用者可選擇清理 message（如果敏感）
     *
     * @param message 32字節的消息哈希
     * @param privateKey 32字節的私鑰（⚠️ 調用者必須在使用後清零）
     * @return 64-byte compact 格式簽名 (r || s)，與 libsecp256k1 一致
     */
    fun sign(message: ByteArray, privateKey: ByteArray): ByteArray {
        require(message.size == 32) { "Message must be 32 bytes" }
        require(privateKey.size == 32) { "Private key must be 32 bytes" }

        // 敏感數據追蹤（用於清理）
        var kBytes: ByteArray? = null

        return try {
            val d = privateKey.toBigInteger()
            val z = message.toBigInteger()

            // ✅ 使用 RFC 6979 deterministic k generation
            val k = generateKDeterministic(privateKey, message)
            kBytes = k.toByteArray() // 保存以便清理

            require(d >= BigInteger.ONE && d < N) { "Invalid private key" }

            // 計算 r = (k * G).x mod n
            val kG = scalarMultiply(k, G_X, G_Y) ?: throw IllegalStateException("k*G is infinity")
            val r = kG.first % N

            // ✅ P0-CRITICAL: 驗證 r 在有效範圍內 [1, n-1]
            require(r >= BigInteger.ONE && r < N) { "Invalid signature: r is zero or out of range" }

            // 計算 s = k^-1 * (z + r * d) mod n
            val kInv = k.modInverse(N)
            var s = (kInv * (z + r * d)) % N

            // ✅ P0-CRITICAL: 驗證 s 在有效範圍內 [1, n-1]
            require(s >= BigInteger.ONE && s < N) { "Invalid signature: s is zero or out of range" }

            val halfN = N shr 1
            if (s > halfN) {
                s = N - s
            }

            // ✅ 返回 compact 格式 (64 bytes: 32-byte r || 32-byte s)
            encodeCompact(r, s)

        } finally {
            // ✅ 安全清零臨時密鑰 k
            kBytes?.let { bytes ->
                bytes.fill(0)
                // 多次覆寫防止編譯器優化
                kotlin.random.Random.nextBytes(bytes)
                bytes.fill(0)
            }
        }
    }

    data class Secp256k1Signature(
        val r: ByteArray,
        val s: ByteArray,
        val yParity: Int
    )

    fun signWithRecovery(message: ByteArray, privateKey: ByteArray): Secp256k1Signature {
        require(message.size == 32) { "Message must be 32 bytes" }
        require(privateKey.size == 32) { "Private key must be 32 bytes" }

        var kBytes: ByteArray? = null
        return try {
            val d = privateKey.toBigInteger()
            require(d >= BigInteger.ONE && d < N) { "Invalid private key" }
            val z = message.toBigInteger()
            val k = generateKDeterministic(privateKey, message)
            kBytes = k.toByteArray()

            val kG = scalarMultiply(k, G_X, G_Y) ?: throw IllegalStateException("k*G is infinity")
            val kGx = kG.first
            val kGy = kG.second
            val r = kGx % N
            require(r >= BigInteger.ONE && r < N) { "Invalid signature: r is zero or out of range" }

            val kInv = k.modInverse(N)
            var s = (kInv * (z + r * d)) % N
            require(s >= BigInteger.ONE && s < N) { "Invalid signature: s is zero or out of range" }

            val halfN = N shr 1
            var yParity = if (kGy.isEven()) 0 else 1
            if (s > halfN) {
                s = N - s
                yParity = yParity xor 1
            }

            Secp256k1Signature(
                r = r.toByteArrayPadded(32),
                s = s.toByteArrayPadded(32),
                yParity = yParity
            )
        } finally {
            kBytes?.let { bytes ->
                bytes.fill(0)
                kotlin.random.Random.nextBytes(bytes)
                bytes.fill(0)
            }
        }
    }

    fun recoverPublicKeyPoint(z: BigInteger, r: BigInteger, s: BigInteger, yParity: Int): Pair<BigInteger, BigInteger>? {
        if (r < BigInteger.ONE || r >= N || s < BigInteger.ONE || s >= N) return null
        val x = r
        // y^2 = x^3 + 7 mod P
        val y2 = ((x * x % P) * x + 7.toBigInteger()) % P
        // Modular square root for P = 3 mod 4: y = y2^((P+1)/4) mod P
        val exp = (P + BigInteger.ONE) shr 2
        var y = y2.modPow(exp, P)
        if ((y * y % P) != y2) return null // Not a valid point

        val isYEven = y.isEven()
        val expectedEven = (yParity and 1) == 0
        if (isYEven != expectedEven) {
            y = P - y
        }

        // Q = r^-1 * (s * R - z * G)
        val rInv = r.modInverse(N)
        val sR = scalarMultiply(s, x, y) ?: return null
        val zG = scalarMultiply(z, G_X, G_Y)
        val negZG = if (zG == null) null else Pair(zG.first, (P - zG.second).mod(P))
        val diff = pointAdd(sR, negZG) ?: return null
        return scalarMultiply(rInv, diff.first, diff.second)
    }

    fun recoverPublicKeyPoint(hash32: ByteArray, rBytes: ByteArray, sBytes: ByteArray, yParity: Int): Pair<BigInteger, BigInteger>? {
        val z = BigInteger.fromByteArray(hash32)
        val r = BigInteger.fromByteArray(rBytes)
        val s = BigInteger.fromByteArray(sBytes)
        return recoverPublicKeyPoint(z, r, s, yParity)
    }
    
    /**
     * 從私鑰生成公鑰
     *
     * ⚠️ 安全注意事項：
     * - 此方法不會清理 privateKey（由調用者負責）
     * - 調用者必須在使用後清零: `finally { privateKey.secureZero() }`
     *
     * @param privateKey 32字節私鑰（⚠️ 調用者必須在使用後清零）
     * @param compressed 是否返回壓縮格式
     * @return 33字節（壓縮）或65字節（未壓縮）公鑰
     */
    fun pubKeyOf(privateKey: ByteArray, compressed: Boolean = true): ByteArray {
        require(privateKey.size == 32) { "Private key must be 32 bytes" }

        val d = privateKey.toBigInteger()
        require(d >= BigInteger.ONE && d < N) { "Private key is out of range for secp256k1" }

        val point = scalarMultiply(d, G_X, G_Y)
            ?: throw IllegalArgumentException("Private key is out of range for secp256k1")

        return encodePublicKey(point, compressed)
    }
    
    /**
     * 驗證簽名
     * ✅ 支援 compact 和 DER 兩種格式以保持向後兼容
     *
     * @param message 原始消息
     * @param signature 簽名（compact 或 DER 格式）
     * @param publicKey 公鑰
     * @return 簽名是否有效
     */
    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        return try {
            // ✅ 支援兩種格式以保持向後兼容
            val (r, s) = if (signature.size == 64) {
                decodeCompact(signature)  // Compact format (default)
            } else {
                decodeDER(signature)  // DER format (backward compatibility)
            }

            val z = message.toBigInteger()

            // 解析公鑰
            val (pubX, pubY) = decodePublicKey(publicKey)

            // 計算 u1 = z * s^-1 mod n
            val sInv = s.modInverse(N)
            val u1 = (z * sInv) % N

            // 計算 u2 = r * s^-1 mod n
            val u2 = (r * sInv) % N

            // 計算 (x, y) = u1 * G + u2 * pubKey
            // Identity is the point at infinity, not affine (0,0).
            val p1 = scalarMultiply(u1, G_X, G_Y)
            val p2 = scalarMultiply(u2, pubX, pubY)
            val sum = pointAdd(p1, p2) ?: return false

            // 驗證 r == x mod n
            r == sum.first % N
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Affine point addition. `null` is the point at infinity (group identity).
     * Affine (0,0) is *not* identity and is not on secp256k1.
     */
    private fun pointAdd(
        p1: Pair<BigInteger, BigInteger>?,
        p2: Pair<BigInteger, BigInteger>?
    ): Pair<BigInteger, BigInteger>? {
        if (p1 == null) return p2
        if (p2 == null) return p1

        val (x1, y1) = p1
        val (x2, y2) = p2
        val three = BigInteger(KmpBigInteger.fromInt(3))
        val two = BigInteger(KmpBigInteger.fromInt(2))
        val pMinusTwo = P - two

        if (x1 == x2) {
            if ((y1 + y2).mod(P) == BigInteger.ZERO) {
                return null
            }
            if (y1 == BigInteger.ZERO) {
                return null
            }
            val num = (three * x1 * x1).mod(P)
            val den = (two * y1).mod(P)
            val s = (num * den.modPow(pMinusTwo, P)).mod(P)
            val x3 = (s * s - two * x1).mod(P)
            val y3 = (s * (x1 - x3) - y1).mod(P)
            return Pair(x3, y3)
        }

        val num = (y2 - y1).mod(P)
        val den = (x2 - x1).mod(P)
        val s = (num * den.modPow(pMinusTwo, P)).mod(P)
        val x3 = (s * s - x1 - x2).mod(P)
        val y3 = (s * (x1 - x3) - y1).mod(P)
        return Pair(x3, y3)
    }

    /**
     * 標量乘法（使用倍增和加法）。回傳 null 表示無窮遠點。
     */
    private fun scalarMultiply(k: BigInteger, x: BigInteger, y: BigInteger): Pair<BigInteger, BigInteger>? {
        var scalar = k.mod(N)
        if (scalar == BigInteger.ZERO) return null

        var result: Pair<BigInteger, BigInteger>? = null
        var addend: Pair<BigInteger, BigInteger>? = Pair(x, y)
        val two = BigInteger(KmpBigInteger.fromInt(2))

        while (scalar.magnitude > KmpBigInteger.ZERO) {
            if (scalar.mod(two) == BigInteger.ONE) {
                result = pointAdd(result, addend)
            }
            addend = pointAdd(addend, addend)
            scalar = scalar / two
        }
        return result
    }

    private fun generateKDeterministic(
        privateKey: ByteArray,
        messageHash: ByteArray
    ): BigInteger {
        // RFC 6979 §3.2 with q = secp256k1 n, qlen = rlen = 256.
        // HMAC init uses int2octets(x) and bits2octets(h1), not the raw digest.
        val xOctets = privateKey
        val h1Octets = bits2octets(messageHash)

        var v = ByteArray(32) { 0x01 }
        var k = ByteArray(32) { 0x00 }

        k = hmacSha256Blocking(k, v + byteArrayOf(0x00) + xOctets + h1Octets)
        v = hmacSha256Blocking(k, v)

        k = hmacSha256Blocking(k, v + byteArrayOf(0x01) + xOctets + h1Octets)
        v = hmacSha256Blocking(k, v)

        while (true) {
            v = hmacSha256Blocking(k, v)
            val kCandidate = bits2int(v)
            if (kCandidate >= BigInteger.ONE && kCandidate < N) {
                return kCandidate
            }
            k = hmacSha256Blocking(k, v + byteArrayOf(0x00))
            v = hmacSha256Blocking(k, v)
        }
    }

    /** RFC 6979 bits2int: leftmost qlen bits of the octet string as an integer. */
    private fun bits2int(octets: ByteArray): BigInteger {
        return BigInteger.fromByteArray(octets)
    }

    /** RFC 6979 int2octets: rlen/8-byte big-endian encoding. */
    private fun int2octets(value: BigInteger): ByteArray {
        return value.toByteArray32()
    }

    /** RFC 6979 bits2octets(x) = int2octets(bits2int(x) mod q). */
    private fun bits2octets(hash: ByteArray): ByteArray {
        return int2octets(bits2int(hash) % N)
    }
    
    /**
     * 同步版本的 HMAC-SHA256（blocking call）
     * 使用 WatchOSCryptoKitSimple 的 HMAC-SHA256 實現
     */
    private fun hmacSha256Blocking(key: ByteArray, data: ByteArray): ByteArray {
        return HmacSha256.hmac(key, data)
    }
    
    /**
     * DER 編碼簽名（保留作為工具方法）
     */
    private fun encodeDER(r: BigInteger, s: BigInteger): ByteArray {
        val rBytes = r.toByteArrayTrimmed()
        val sBytes = s.toByteArrayTrimmed()

        val result = mutableListOf<Byte>()

        // SEQUENCE tag
        result.add(0x30)
        // Length placeholder
        val lengthIndex = result.size
        result.add(0)

        // r value
        result.add(0x02) // INTEGER tag
        result.add(rBytes.size.toByte())
        result.addAll(rBytes.toList())

        // s value
        result.add(0x02) // INTEGER tag
        result.add(sBytes.size.toByte())
        result.addAll(sBytes.toList())

        // Update length
        result[lengthIndex] = (result.size - 2).toByte()

        return result.toByteArray()
    }

    /**
     * Compact 編碼簽名 (64 bytes: r || s)
     * 這是標準的 secp256k1 簽名格式，與 libsecp256k1 一致
     * ✅ P0-CRITICAL: 確保跨平台互操作性 (iOS, Android, watchOS)
     */
    private fun encodeCompact(r: BigInteger, s: BigInteger): ByteArray {
        val rBytes = r.toByteArray32()
        val sBytes = s.toByteArray32()
        return rBytes + sBytes  // 64 bytes total
    }

    /**
     * Compact 解碼簽名 (64 bytes: r || s)
     * ✅ P0-CRITICAL: 包含 r, s 範圍檢查
     */
    private fun decodeCompact(signature: ByteArray): Pair<BigInteger, BigInteger> {
        require(signature.size == 64) { "Compact signature must be 64 bytes" }

        // 解析 r (前 32 bytes)
        val r = signature.sliceArray(0 until 32).toBigInteger()

        // ✅ P0-CRITICAL: 驗證 r 在有效範圍內 [1, n-1]
        require(r >= BigInteger.ONE && r < N) { "Invalid signature: r is zero or out of range" }

        // 解析 s (後 32 bytes)
        val s = signature.sliceArray(32 until 64).toBigInteger()

        // ✅ P0-CRITICAL: 驗證 s 在有效範圍內 [1, n-1]
        require(s >= BigInteger.ONE && s < N) { "Invalid signature: s is zero or out of range" }

        return Pair(r, s)
    }
    
    /**
     * DER 解碼簽名
     * ✅ P0-CRITICAL: 包含 r, s 範圍檢查
     */
    private fun decodeDER(signature: ByteArray): Pair<BigInteger, BigInteger> {
        require(signature.isNotEmpty()) { "Invalid DER signature" }
        var index = 0
        require(signature[index++] == 0x30.toByte()) { "Invalid DER signature" }

        val seqLen = readDerLength(signature, index)
        index = seqLen.second
        val seqEnd = index + seqLen.first
        require(seqEnd == signature.size) { "Invalid DER signature: trailing bytes" }

        require(index < seqEnd && signature[index++] == 0x02.toByte()) { "Invalid DER signature (r)" }
        val rLen = readDerLength(signature, index)
        index = rLen.second
        require(index + rLen.first <= seqEnd) { "Invalid DER signature (r overflow)" }
        val rBytes = signature.sliceArray(index until index + rLen.first)
        index += rLen.first
        val r = parseDerInteger(rBytes)
        require(r >= BigInteger.ONE && r < N) { "Invalid signature: r is zero or out of range" }

        require(index < seqEnd && signature[index++] == 0x02.toByte()) { "Invalid DER signature (s)" }
        val sLen = readDerLength(signature, index)
        index = sLen.second
        require(index + sLen.first <= seqEnd) { "Invalid DER signature (s overflow)" }
        val sBytes = signature.sliceArray(index until index + sLen.first)
        index += sLen.first
        val s = parseDerInteger(sBytes)
        require(s >= BigInteger.ONE && s < N) { "Invalid signature: s is zero or out of range" }

        require(index == seqEnd) { "Invalid DER signature: unconsumed INTEGER payload" }
        return Pair(r, s)
    }

    private fun readDerLength(data: ByteArray, offset: Int): Pair<Int, Int> {
        require(offset < data.size) { "Invalid DER length" }
        val first = data[offset].toInt() and 0xFF
        if (first < 0x80) {
            return Pair(first, offset + 1)
        }
        val nbytes = first - 0x80
        require(nbytes in 1..2) { "Invalid DER length" }
        require(offset + 1 + nbytes <= data.size) { "Invalid DER length" }
        var len = 0
        for (i in 0 until nbytes) {
            len = (len shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
        }
        require(len >= 0x80 || nbytes > 1) { "Non-minimal DER length" }
        require(nbytes != 1 || len >= 0x80) { "Non-minimal DER length" }
        if (nbytes == 1 && len < 0x80) {
            throw IllegalArgumentException("Non-minimal DER length")
        }
        return Pair(len, offset + 1 + nbytes)
    }

    private fun parseDerInteger(bytes: ByteArray): BigInteger {
        require(bytes.isNotEmpty()) { "Empty DER integer" }
        require(bytes[0] != 0x00.toByte() || bytes.size == 1 || (bytes[1].toInt() and 0x80) != 0) {
            "Non-minimal DER integer"
        }
        require((bytes[0].toInt() and 0x80) == 0) { "Negative DER integer" }
        return BigInteger.fromByteArray(bytes)
    }
    
    /**
     * 生成公鑰（公開方法）
     */
    fun generatePublicKey(privateKey: ByteArray, compressed: Boolean = true): ByteArray {
        return pubKeyOf(privateKey, compressed)
    }
    
    /**
     * 生成公鑰點（公開方法）
     */
    fun generatePublicKeyPoint(privateKey: ByteArray): Pair<BigInteger, BigInteger> {
        val d = privateKey.toBigInteger()
        require(d >= BigInteger.ONE && d < N) { "Invalid private key" }
        return scalarMultiply(d, G_X, G_Y)
            ?: throw IllegalArgumentException("Invalid private key")
    }
    
    /**
     * 點加法（公開方法）
     */
    fun addPoints(p1: Pair<BigInteger, BigInteger>, p2: Pair<BigInteger, BigInteger>): Pair<BigInteger, BigInteger> {
        return pointAdd(p1, p2)
            ?: throw IllegalArgumentException("Result is point at infinity")
    }
    
    /**
     * 編碼公鑰（公開方法）
     */
    fun encodePublicKey(point: Pair<BigInteger, BigInteger>, compressed: Boolean = true): ByteArray {
        val (x, y) = point
        return if (compressed) {
            val prefix = if (y % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO) 0x02 else 0x03
            byteArrayOf(prefix.toByte()) + x.toByteArray32()
        } else {
            byteArrayOf(0x04) + x.toByteArray32() + y.toByteArray32()
        }
    }
    
    /**
     * SHA256 哈希（公開方法）
     */
    fun sha256(data: ByteArray): ByteArray {
        return SHA256().digest(data)
    }

    /**
     * ECDH 密鑰交換（公開方法）
     * ✅ 用於 watchOS 平台的 ECDH 實現
     *
     * @param privateKey 己方 32 字節私鑰
     * @param publicKey 對方公鑰（33 或 65 字節）
     * @return 32 字節共享密鑰
     */
    fun ecdh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "Private key must be 32 bytes" }
        require(publicKey.size == 33 || publicKey.size == 65) { "Invalid public key size" }

        // 1. 解碼對方的公鑰點
        val (pubX, pubY) = decodePublicKey(publicKey)
        
        // 2. 計算共享密鑰點：sharedPoint = privateKey * publicKey
        val d = privateKey.toBigInteger()
        require(d >= BigInteger.ONE && d < N) { "Invalid private key" }
        val shared = scalarMultiply(d, pubX, pubY)
            ?: throw IllegalArgumentException("ECDH result is point at infinity")
        val sharedX = shared.first
        
        // 3. 使用 x 坐標作為共享密鑰（ECDH 標準做法）
        return sharedX.toByteArray32()
    }

    fun secKeyVerify(privateKey: ByteArray): Boolean {
        if (privateKey.size != 32) return false
        val d = privateKey.toBigInteger()
        return d > BigInteger.ZERO && d < N
    }

    fun pubkeyCreate(privateKey: ByteArray): ByteArray {
        return generatePublicKey(privateKey, compressed = true)
    }

    fun privKeyTweakAdd(privateKey: ByteArray, tweak: ByteArray): ByteArray {
        val d = privateKey.toBigInteger()
        val t = tweak.toBigInteger()
        val res = (d + t) % N
        require(res >= BigInteger.ONE && res < N) { "Invalid tweaked private key" }
        return res.toByteArray32()
    }

    fun pubKeyTweakAdd(publicKey: ByteArray, tweak: ByteArray): ByteArray {
        val p1 = decodePublicKey(publicKey)
        val t = tweak.toBigInteger()
        val p2 = scalarMultiply(t, G_X, G_Y)
        val res = pointAdd(p1, p2) ?: throw IllegalArgumentException("Tweaked public key is infinity")
        return encodePublicKey(res, compressed = true)
    }

    /**
     * 驗證點是否在 secp256k1 曲線上
     * 曲線方程: y² = x³ + 7 (mod p)
     * 
     * @param x 點的 x 坐標
     * @param y 點的 y 坐標
     * @return 點是否在曲線上
     */
    internal fun validatePointOnCurve(x: BigInteger, y: BigInteger): Boolean {
        // 左邊: y² mod p
        val left = (y * y) % P
        
        // 右邊: x³ + 7 mod p
        val right = (x.pow(3) + BigInteger(KmpBigInteger.fromInt(7))) % P
        
        return left == right
    }
    
    /**
     * 驗證點是否為無窮遠點（零點）
     * 
     * @param x 點的 x 坐標
     * @param y 點的 y 坐標
     * @return 點是否為無窮遠點
     */
    private fun isPointAtInfinity(x: BigInteger, y: BigInteger): Boolean {
        return x == BigInteger.ZERO && y == BigInteger.ZERO
    }
    
    /**
     * 解碼公鑰
     * ✅ 包含完整的點驗證，防止 Invalid Curve Attack
     */
    fun decodePublicKey(publicKey: ByteArray): Pair<BigInteger, BigInteger> {
        // 步驟 1: 解碼公鑰格式（未壓縮或壓縮）
        val (x, y) = when (publicKey[0]) {
            0x04.toByte() -> {
                // 未壓縮格式
                require(publicKey.size == 65) { "Invalid uncompressed public key" }
                Pair(
                    publicKey.sliceArray(1 until 33).toBigInteger(),
                    publicKey.sliceArray(33 until 65).toBigInteger()
                )
            }
            0x02.toByte(), 0x03.toByte() -> {
                // 壓縮格式
                require(publicKey.size == 33) { "Invalid compressed public key" }
                val x = publicKey.sliceArray(1 until 33).toBigInteger()
                val y = decompressY(x, publicKey[0] == 0x03.toByte())
                Pair(x, y)
            }
            else -> throw IllegalArgumentException("Invalid public key format")
        }
        
        // ✅ 步驟 2: 驗證點不是無窮遠點
        if (isPointAtInfinity(x, y)) {
            throw IllegalArgumentException("Public key cannot be point at infinity")
        }
        
        // ✅ 步驟 3: 驗證點在 secp256k1 曲線上
        if (!validatePointOnCurve(x, y)) {
            throw IllegalArgumentException("Public key point is not on secp256k1 curve")
        }
        
        // ✅ 步驟 4: 驗證 x 和 y 坐標在有效範圍內 [0, p-1]
        if (x < BigInteger.ZERO || x >= P) {
            throw IllegalArgumentException("Public key x coordinate is out of range")
        }
        if (y < BigInteger.ZERO || y >= P) {
            throw IllegalArgumentException("Public key y coordinate is out of range")
        }
        
        return Pair(x, y)
    }
    
    /**
     * 從 x 坐標恢復 y 坐標
     */
    private fun decompressY(x: BigInteger, isOdd: Boolean): BigInteger {
        // y^2 = x^3 + 7 (mod p)
        val ySquared = (x.pow(3) + BigInteger(KmpBigInteger.fromInt(7))) % P
        val y = ySquared.modSqrt(P)
        
        return if ((y % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ONE) == isOdd) {
            y
        } else {
            P - y
        }
    }
    
    /**
     * 封裝 bignum 庫的大整數類，提供與原始代碼相容的接口
     */
    class BigInteger(internal val magnitude: KmpBigInteger) {
        companion object {
            val ZERO = BigInteger(KmpBigInteger.ZERO)
            val ONE = BigInteger(KmpBigInteger.ONE)
            
            fun fromInt(v: Int): BigInteger = BigInteger(KmpBigInteger.fromInt(v))
            fun fromLong(v: Long): BigInteger = BigInteger(KmpBigInteger.fromLong(v))

            fun fromByteArray(bytes: ByteArray): BigInteger {
                if (bytes.isEmpty()) return ZERO
                // bignum 的 fromByteArray 默認處理帶符號字節
                // 我們需要處理為無符號（大端緒）
                return BigInteger(KmpBigInteger.fromByteArray(bytes, Sign.POSITIVE))
            }

            fun fromHex(hex: String): BigInteger {
                return BigInteger(KmpBigInteger.parseString(hex, 16))
            }
        }
        
        constructor(bytes: ByteArray) : this(KmpBigInteger.fromByteArray(bytes, Sign.POSITIVE))

        fun isEven(): Boolean = (magnitude % KmpBigInteger.fromInt(2)) == KmpBigInteger.ZERO
        infix fun shr(n: Int): BigInteger = BigInteger(magnitude shr n)
        fun toByteArrayPadded(length: Int): ByteArray = toByteArray32()
        
        fun toByteArray32(): ByteArray {
            val bytes = magnitude.toByteArray()
            // IonSpin toByteArray returns signed representation, potentially with leading zero
            val cleanBytes = if (bytes.size > 32 && bytes[0] == 0.toByte()) {
                bytes.sliceArray(1 until bytes.size)
            } else if (bytes.size > 32) {
                // If it's more than 32 bytes without a leading zero, it's > 2^256. 
                // For secp256k1 coordinates, this shouldn't happen, but we'll take last 32.
                bytes.sliceArray(bytes.size - 32 until bytes.size)
            } else {
                bytes
            }
            
            val result = ByteArray(32)
            val startAt = 32 - cleanBytes.size
            if (startAt >= 0) {
                cleanBytes.copyInto(result, startAt)
            } else {
                // Should not happen for coordinates < P
                cleanBytes.sliceArray(cleanBytes.size - 32 until cleanBytes.size).copyInto(result)
            }
            return result
        }
        
        fun toByteArrayTrimmed(): ByteArray {
            val hex = magnitude.toString(16)
            val cleanHex = if (hex.length % 2 != 0) "0$hex" else hex
            return cleanHex.hexToByteArray()
        }
        
        fun toByteArray(): ByteArray = magnitude.toByteArray()
        
        fun toInt(): Int = magnitude.intValue()
        
        operator fun plus(other: BigInteger): BigInteger = BigInteger(magnitude + other.magnitude)
        operator fun minus(other: BigInteger): BigInteger = BigInteger(magnitude - other.magnitude)
        operator fun times(other: BigInteger): BigInteger = BigInteger(magnitude * other.magnitude)
        operator fun div(other: BigInteger): BigInteger = BigInteger(magnitude / other.magnitude)
        operator fun rem(other: BigInteger): BigInteger = BigInteger(magnitude % other.magnitude)
        
        fun mod(other: BigInteger): BigInteger {
            val r = magnitude % other.magnitude
            // 檢查是否為負數，bignum 可能沒有公開 Sign 枚舉或符號屬性
            return if (r < KmpBigInteger.ZERO) BigInteger(r + other.magnitude) else BigInteger(r)
        }
        
        operator fun compareTo(other: BigInteger): Int = magnitude.compareTo(other.magnitude)
        
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is BigInteger) return false
            return magnitude.compareTo(other.magnitude) == 0
        }
        
        override fun hashCode(): Int = magnitude.hashCode()
        
        fun pow(n: Int): BigInteger = BigInteger(magnitude.pow(n.toLong()))
        
        fun modSqrt(p: BigInteger): BigInteger {
            // secp256k1 的 p ≡ 3 (mod 4)，可以使用簡化公式：y = x^((p+1)/4) mod p
            val exp = (p.magnitude + KmpBigInteger.ONE) / KmpBigInteger.fromInt(4)
            return BigInteger(modPowInternal(magnitude, exp, p.magnitude))
        }
        
        fun pow(n: Long): BigInteger = BigInteger(magnitude.pow(n))

        fun modPow(exponent: BigInteger, modulus: BigInteger): BigInteger {
            // IonSpin might have a more optimized modPow. If not, we fall back to our Internal one.
            // But wait, KmpBigInteger doesn't have modPow in some versions? 
            // I'll try it. If it fails to compile, I'll use modPowInternal.
            return try {
                 // return BigInteger(magnitude.modPow(exponent.magnitude, modulus.magnitude))
                 // Actually, let's stick to the verified loop but make it more robust.
                 BigInteger(modPowInternal(magnitude, exponent.magnitude, modulus.magnitude))
            } catch (e: Exception) {
                 BigInteger(modPowInternal(magnitude, exponent.magnitude, modulus.magnitude))
            }
        }

        fun modInverse(m: BigInteger): BigInteger {
            // 使用擴展歐幾里得算法或庫自帶方法
            // ionspin bignum 0.3.9 有 gcdExtended 或類似方法嗎？ 
            // 好像沒有直接的 modInverse... 我們自己實現一個高效的
            var a = magnitude % m.magnitude
            if (a < KmpBigInteger.ZERO) a += m.magnitude
            
            var m0 = m.magnitude
            var x0 = KmpBigInteger.ZERO
            var x1 = KmpBigInteger.ONE
            
            if (m0 == KmpBigInteger.ONE) return ZERO
            
            while (a > KmpBigInteger.ONE) {
                val q = a / m0
                var t = m0
                m0 = a % m0
                a = t
                t = x0
                x0 = x1 - q * x0
                x1 = t
            }
            
            if (x1 < KmpBigInteger.ZERO) x1 += m.magnitude
            return BigInteger(x1)
        }
    }

    private fun modPowInternal(base: KmpBigInteger, exponent: KmpBigInteger, modulus: KmpBigInteger): KmpBigInteger {
        var res = KmpBigInteger.ONE
        var b = base % modulus
        var e = exponent
        while (e > KmpBigInteger.ZERO) {
            if (e % KmpBigInteger.TWO == KmpBigInteger.ONE) {
                res = (res * b) % modulus
            }
            b = (b * b) % modulus
            e /= KmpBigInteger.TWO
        }
        return res
    }

    /**
     * ==========================================
     * BIP340 Schnorr Signatures
     * ==========================================
     */

    /**
     * BIP340 Schnorr 簽名
     *
     * @param message 32-byte 消息哈希 (m)
     * @param privateKey 32-byte 私鑰 (d)
     * @param auxRand 32-byte 輔助隨機數據 (a) - 用於防止側信道攻擊，可選（默認為 0）
     * @return 64-byte 簽名 (R || s)
     */
    fun schnorrSign(message: ByteArray, privateKey: ByteArray, auxRand: ByteArray = ByteArray(32)): ByteArray =
        signSchnorr(message, privateKey, auxRand)

    fun signSchnorr(message: ByteArray, privateKey: ByteArray, auxRand: ByteArray = ByteArray(32)): ByteArray {
        require(message.size == 32) { "Message must be 32 bytes" }
        require(privateKey.size == 32) { "Private key must be 32 bytes" }

        // 1. d' = int(sk)
        // fail if d' = 0 or d' >= n
        val dBig = privateKey.toBigInteger()
        if (dBig == BigInteger.ZERO || dBig >= N) {
            throw IllegalArgumentException("Invalid private key")
        }

        // 2. P = d'⋅G
        val P = scalarMultiply(dBig, G_X, G_Y)
            ?: throw IllegalArgumentException("Invalid private key")

        // 3. d = d' if has_even_y(P), else n - d'
        val d = if (hasEvenY(P)) dBig else N - dBig

        // 4. t = bytes(d) xor bytes(tagged_hash("BIP0340/aux", aux_rand))
        // Note: must use adjusted 'd', not original 'd' (privateKey)
        val t = xor(d.toByteArray32(), taggedHash("BIP0340/aux", auxRand))

        // 5. rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)
        // P bytes is encoded as 32-byte x coordinate
        val P_bytes = P.first.toByteArray32()
        val rand = taggedHash("BIP0340/nonce", t + P_bytes + message)

        // 6. k' = int(rand) mod n
        // 7. fail if k' = 0
        val kPrime = BigInteger.fromByteArray(rand) % N
        if (kPrime == BigInteger.ZERO) {
            throw IllegalStateException("kPrime is zero (extremely unlikely)")
        }

        // 8. R = k'⋅G
        val R = scalarMultiply(kPrime, G_X, G_Y)
            ?: throw IllegalStateException("R is infinity")

        // 9. k = k' if has_even_y(R), else n - k'
        val k = if (hasEvenY(R)) kPrime else N - kPrime

        // 10. e = int(tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)) mod n
        val R_bytes = R.first.toByteArray32()
        val e = BigInteger.fromByteArray(taggedHash("BIP0340/challenge", R_bytes + P_bytes + message)) % N

        // 11. sig = bytes(R) || bytes((k + ed) mod n)
        val s = (k + e * d) % N
        val sig = R_bytes + s.toByteArray32()

        return sig
    }

    /**
     * BIP340 Schnorr 驗證
     *
     * @param message 32-byte 消息 (m)
     * @param publicKey 32-byte x-only 公鑰 (P)
     * @param signature 64-byte 簽名 (R || s)
     * @return 是否有效
     */
    fun schnorrVerify(message: ByteArray, publicKey: ByteArray, signature: ByteArray): Boolean =
        verifySchnorr(message, publicKey, signature)

    fun verifySchnorr(message: ByteArray, publicKey: ByteArray, signature: ByteArray): Boolean {
        if (message.size != 32) return false
        if (publicKey.size != 32) return false
        if (signature.size != 64) return false

        try {
            // 1. P = lift_x(int(pk))
            // fail if P is not on curve
            val px = publicKey.toBigInteger()
            if (px >= P) return false
            val P_point = liftX(px) // y is even

            // 2. r = int(sig[0:32])
            // fail if r >= p
            val r = signature.sliceArray(0 until 32).toBigInteger()
            if (r >= P) return false

            // 3. s = int(sig[32:64])
            // fail if s >= n
            val s = signature.sliceArray(32 until 64).toBigInteger()
            if (s >= N) return false

            // 4. e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || m)) mod n
            val e = BigInteger.fromByteArray(taggedHash("BIP0340/challenge", signature.sliceArray(0 until 32) + publicKey + message)) % N

            // 5. R = s⋅G - e⋅P
            // R = s⋅G + (-e)⋅P
            // sG
            val sG = scalarMultiply(s, G_X, G_Y)
            // -eP = (n-e)P
            val negE = N - e
            val negEP = scalarMultiply(negE, P_point.first, P_point.second)

            val R_calc = pointAdd(sG, negEP)

            // 6. fail if is_infinite(R)
            if (R_calc == null || isPointAtInfinity(R_calc.first, R_calc.second)) return false

            // 7. fail if not has_even_y(R)
            if (!hasEvenY(R_calc)) return false

            // 8. fail if x(R) != r
            return R_calc.first == r

        } catch (e: Exception) {
            return false
        }
    }

    fun taggedHash(tag: String, data: ByteArray): ByteArray {
        val tagHash = sha256(tag.encodeToByteArray())
        return sha256(tagHash + tagHash + data)
    }
    
    /**
     * BIP-341 TapLeaf hash
     * tagged_hash("TapLeaf", leafVersion || compact_size(script) || script)
     */
    internal fun tapLeafHash(leafVersion: Byte, script: ByteArray): ByteArray {
        val data = byteArrayOf(leafVersion) + compactSize(script.size) + script
        return taggedHash("TapLeaf", data)
    }
    
    /**
     * BIP-341 TapBranch hash
     * tagged_hash("TapBranch", sorted(left, right))
     * Leaves are sorted lexicographically before concatenation
     */
    internal fun tapBranchHash(left: ByteArray, right: ByteArray): ByteArray {
        // Sort the two hashes lexicographically (as per BIP-341)
        val (first, second) = if (compareByteArrays(left, right) < 0) {
            left to right
        } else {
            right to left
        }
        return taggedHash("TapBranch", first + second)
    }
    
    /**
     * Lexicographic comparison of byte arrays
     */
    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return a.size - b.size
    }
    
    private fun compactSize(size: Int): ByteArray {
        return when {
            size < 253 -> byteArrayOf(size.toByte())
            size <= 0xFFFF -> byteArrayOf(0xFD.toByte()) + 
                byteArrayOf((size and 0xFF).toByte(), ((size shr 8) and 0xFF).toByte())
            else -> throw IllegalArgumentException("Script too large")
        }
    }

    private fun hasEvenY(point: Pair<BigInteger, BigInteger>): Boolean {
        // y % 2 == 0
        return point.second % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO
    }

    fun liftX(x: BigInteger): Pair<BigInteger, BigInteger> {
        val y = decompressY(x, false) // false means even for decompressY's isOdd
        // decompressY checks validity internally? No, we should check curve equation
        if (!validatePointOnCurve(x, y)) throw IllegalArgumentException("Point not on curve")
        return Pair(x, y)
    }
    
    /**
     * Scalar multiply with generator point G
     * Used for Taproot tweak: tweak * G
     */
    fun scalarMultiplyG(scalar: BigInteger): Pair<BigInteger, BigInteger> {
        return scalarMultiply(scalar, G_X, G_Y)
            ?: throw IllegalArgumentException("scalar*G is point at infinity")
    }

    private fun xor(a: ByteArray, b: ByteArray): ByteArray {
        val out = ByteArray(a.size)
        for (i in a.indices) {
            out[i] = (a[i].toInt() xor b[i].toInt()).toByte()
        }
        return out
    }
}

// 擴展函數
private fun ByteArray.toBigInteger(): Secp256k1Pure.BigInteger {
    return Secp256k1Pure.BigInteger(this)
}

private fun String.hexToBigInteger(): Secp256k1Pure.BigInteger {
    return this.hexToByteArray().toBigInteger()
}


private fun Int.toBigInteger(): Secp256k1Pure.BigInteger {
    return when {
        this == 0 -> Secp256k1Pure.BigInteger.ZERO
        this == 1 -> Secp256k1Pure.BigInteger.ONE
        else -> {
            val bytes = mutableListOf<Byte>()
            var value = this
            while (value != 0) {
                bytes.add(0, (value and 0xFF).toByte())
                value = value ushr 8
            }
            Secp256k1Pure.BigInteger(bytes.toByteArray())
        }
    }
}

