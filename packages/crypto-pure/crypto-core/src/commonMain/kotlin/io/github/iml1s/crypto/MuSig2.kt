package io.github.iml1s.crypto

import org.kotlincrypto.hash.sha2.SHA256
import com.ionspin.kotlin.bignum.integer.BigInteger as KmpBigInteger
import com.ionspin.kotlin.bignum.integer.Sign

/**
 * MuSig2 (BIP-327) Implementation
 * 
 * Multi-signature scheme for BIP340-compatible Schnorr signatures.
 * Reference: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
 * 
 * ⚠️ Security Notes:
 * - This is a reference implementation for educational/testing purposes.
 * - Production use should undergo security audit.
 * - Nonce values must be handled with extreme care to prevent key leakage.
 */
object MuSig2 {
    
    // secp256k1 curve parameters
    private val P = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    private val N = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    private val G_X = BigInteger.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    private val G_Y = BigInteger.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
    
    // ========================
    // Data Structures
    // ========================
    
    /**
     * Key aggregation context containing:
     * - Q: Aggregated public key point (stored as 32-byte x and y coordinates)
     * - gacc: Accumulated negation indicator (32 bytes)
     * - tacc: Accumulated tweak value (32 bytes)
     */
    data class KeyAggContext(
        val qXBytes: ByteArray,
        val qYBytes: ByteArray,
        val gaccBytes: ByteArray,
        val taccBytes: ByteArray
    )
    
    /**
     * Session context for signing
     */
    data class SessionContext(
        val aggnonce: ByteArray,
        val pubkeys: List<ByteArray>,
        val tweaks: List<ByteArray>,
        val isXonly: List<Boolean>,
        val msg: ByteArray
    )
    
    /**
     * Exception for invalid contribution from a signer
     */
    class InvalidContributionError(val signer: Int?, val contrib: String) : Exception(
        "Invalid contribution from signer $signer: $contrib"
    )
    
    // ========================
    // Tagged Hashing (BIP-340)
    // ========================
    
    /**
     * Compute tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
     */
    fun taggedHash(tag: String, msg: ByteArray): ByteArray {
        val tagHash = sha256(tag.encodeToByteArray())
        return sha256(tagHash + tagHash + msg)
    }
    
    private fun sha256(data: ByteArray): ByteArray {
        val digest = SHA256()
        digest.update(data)
        return digest.digest()
    }
    
    // ========================
    // Point Operations
    // ========================
    
    private fun bytesFromInt(x: BigInteger): ByteArray {
        val bytes = x.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
            bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
            else -> throw IllegalArgumentException("Value too large: ${bytes.size} bytes")
        }
    }
    
    private fun intFromBytes(b: ByteArray): BigInteger {
        return BigInteger.fromByteArray(b)
    }
    
    /**
     * Lift x-coordinate to curve point (returns even-y point)
     */
    private fun liftX(xBytes: ByteArray): Pair<BigInteger, BigInteger>? {
        val x = intFromBytes(xBytes)
        if (x >= P) return null
        
        // y² = x³ + 7 (mod p)
        val three = BigInteger.fromInt(3)
        val seven = BigInteger.fromInt(7)
        val xCubed = x * x * x
        val ySq = (xCubed.mod(P) + seven).mod(P)
        
        // y = y_sq ^ ((p + 1) / 4) mod p (Tonelli-Shanks shortcut for p ≡ 3 mod 4)
        val exp = (P + BigInteger.ONE) / BigInteger.fromInt(4)
        val y = modPow(ySq, exp, P)
        
        // Verify y² = y_sq
        val ySquared = (y * y).mod(P)
        if (ySquared != ySq) return null
        
        // Return even y
        return if (y.mod(BigInteger.fromInt(2)) == BigInteger.ZERO) {
            Pair(x, y)
        } else {
            Pair(x, P - y)
        }
    }
    
    /**
     * Modular exponentiation: base^exp mod mod
     */
    private fun modPow(base: BigInteger, exp: BigInteger, mod: BigInteger): BigInteger {
        var result = BigInteger.ONE
        var b = base.mod(mod)
        var e = exp
        val two = BigInteger.fromInt(2)
        
        while (e > BigInteger.ZERO) {
            if (e.mod(two) == BigInteger.ONE) {
                result = (result * b).mod(mod)
            }
            e = e / two
            b = (b * b).mod(mod)
        }
        return result
    }
    
    /**
     * Check if point has even y-coordinate
     */
    private fun hasEvenY(y: BigInteger): Boolean {
        return y.mod(BigInteger.fromInt(2)) == BigInteger.ZERO
    }
    
    /**
     * Point addition
     */
    private fun pointAdd(
        p1: Pair<BigInteger, BigInteger>?, 
        p2: Pair<BigInteger, BigInteger>?
    ): Pair<BigInteger, BigInteger>? {
        if (p1 == null) return p2
        if (p2 == null) return p1
        
        val (x1, y1) = p1
        val (x2, y2) = p2
        
        // Check for inverse points (sum = infinity)
        if (x1 == x2 && y1 != y2) return null
        
        val two = BigInteger.fromInt(2)
        val three = BigInteger.fromInt(3)
        val pMinusTwo = P - two
        
        val lam = if (p1 == p2) {
            // Point doubling: λ = (3x²) / (2y)
            val num = (three * x1 * x1).mod(P)
            val den = (two * y1).mod(P)
            (num * den.modPow(pMinusTwo, P)).mod(P)
        } else {
            // General addition: λ = (y2 - y1) / (x2 - x1)
            val num = (y2 - y1).mod(P)
            val den = (x2 - x1).mod(P)
            (num * den.modPow(pMinusTwo, P)).mod(P)
        }
        
        val x3 = (lam * lam - x1 - x2).mod(P)
        val y3 = (lam * (x1 - x3) - y1).mod(P)
        
        return Pair(x3, y3)
    }
    
    /**
     * Scalar multiplication using double-and-add
     */
    private fun pointMul(p: Pair<BigInteger, BigInteger>?, n: BigInteger): Pair<BigInteger, BigInteger>? {
        if (p == null) return null
        if (n == BigInteger.ZERO) return null
        
        var result: Pair<BigInteger, BigInteger>? = null
        var addend: Pair<BigInteger, BigInteger>? = p
        var scalar = n
        
        val two = BigInteger.fromInt(2)
        
        for (i in 0 until 256) {
            if (scalar.mod(two) == BigInteger.ONE) {
                result = pointAdd(result, addend)
            }
            addend = pointAdd(addend, addend)
            scalar = scalar / two
        }
        
        return result
    }
    
    /**
     * Negate a point
     */
    private fun pointNegate(p: Pair<BigInteger, BigInteger>?): Pair<BigInteger, BigInteger>? {
        if (p == null) return null
        return Pair(p.first, P - p.second)
    }
    
    /**
     * Get x-only bytes from point
     */
    private fun xbytes(p: Pair<BigInteger, BigInteger>): ByteArray {
        return bytesFromInt(p.first)
    }
    
    /**
     * Encode point as compressed public key (33 bytes)
     */
    private fun cbytes(p: Pair<BigInteger, BigInteger>): ByteArray {
        val prefix = if (hasEvenY(p.second)) 0x02.toByte() else 0x03.toByte()
        return byteArrayOf(prefix) + xbytes(p)
    }
    
    /**
     * Decode compressed public key to point
     */
    private fun cpoint(x: ByteArray): Pair<BigInteger, BigInteger> {
        require(x.size == 33) { "Compressed pubkey must be 33 bytes" }
        
        val point = liftX(x.copyOfRange(1, 33))
            ?: throw IllegalArgumentException("Invalid compressed point")
        
        return when (x[0].toInt() and 0xFF) {
            0x02 -> point
            0x03 -> pointNegate(point) ?: throw IllegalArgumentException("Invalid point")
            else -> throw IllegalArgumentException("Invalid prefix: ${x[0]}")
        }
    }
    
    // ========================
    // Key Aggregation
    // ========================
    
    /**
     * Generate plain public key from secret key (33-byte compressed format)
     */
    fun individualPk(seckey: ByteArray): ByteArray {
        require(seckey.size == 32) { "Secret key must be 32 bytes" }
        val d = intFromBytes(seckey)
        require(d >= BigInteger.ONE && d < N) { "Secret key out of range" }
        
        val p = pointMul(Pair(G_X, G_Y), d)
            ?: throw IllegalArgumentException("Invalid secret key")
        
        return cbytes(p)
    }
    
    /**
     * Sort public keys lexicographically
     */
    fun keySort(pubkeys: List<ByteArray>): List<ByteArray> {
        return pubkeys.sortedWith { a, b ->
            for (i in a.indices) {
                val cmp = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
                if (cmp != 0) return@sortedWith cmp
            }
            0
        }
    }
    
    /**
     * Hash all public keys for key aggregation coefficient
     */
    private fun hashKeys(pubkeys: List<ByteArray>): ByteArray {
        var data = ByteArray(0)
        for (pk in pubkeys) {
            data += pk
        }
        return taggedHash("KeyAgg list", data)
    }
    
    /**
     * Get the second unique key (used for coefficient calculation)
     */
    private fun getSecondKey(pubkeys: List<ByteArray>): ByteArray {
        for (j in 1 until pubkeys.size) {
            if (!pubkeys[j].contentEquals(pubkeys[0])) {
                return pubkeys[j]
            }
        }
        return ByteArray(33) // All zeros indicates no second key
    }
    
    /**
     * Calculate key aggregation coefficient (internal)
     */
    private fun keyAggCoeff(pubkeys: List<ByteArray>, pk: ByteArray): BigInteger {
        val pk2 = getSecondKey(pubkeys)
        return keyAggCoeffInternal(pubkeys, pk, pk2)
    }
    
    private fun keyAggCoeffInternal(pubkeys: List<ByteArray>, pk: ByteArray, pk2: ByteArray): BigInteger {
        // Optimization: second key has coefficient 1
        if (pk.contentEquals(pk2)) {
            return BigInteger.ONE
        }
        
        val L = hashKeys(pubkeys)
        val hash = taggedHash("KeyAgg coefficient", L + pk)
        return intFromBytes(hash).mod(N)
    }
    
    /**
     * Aggregate public keys into a single point
     */
    fun keyAgg(pubkeys: List<ByteArray>): KeyAggContext {
        require(pubkeys.isNotEmpty()) { "Must have at least one public key" }
        
        val pk2 = getSecondKey(pubkeys)
        var q: Pair<BigInteger, BigInteger>? = null
        
        for (i in pubkeys.indices) {
            val pi = try {
                cpoint(pubkeys[i])
            } catch (e: Exception) {
                throw InvalidContributionError(i, "pubkey")
            }
            
            val ai = keyAggCoeffInternal(pubkeys, pubkeys[i], pk2)
            val aiPi = pointMul(pi, ai)
            q = pointAdd(q, aiPi)
        }
        
        // Q should not be infinity except with negligible probability
        requireNotNull(q) { "Aggregated key is point at infinity" }
        
        return KeyAggContext(
            qXBytes = bytesFromInt(q.first),
            qYBytes = bytesFromInt(q.second),
            gaccBytes = bytesFromInt(BigInteger.ONE),
            taccBytes = bytesFromInt(BigInteger.ZERO)
        )
    }
    
    /**
     * Get x-only public key from KeyAggContext
     */
    fun getXonlyPk(ctx: KeyAggContext): ByteArray {
        return ctx.qXBytes
    }
    
    /**
     * Apply a tweak to the aggregated key
     */
    fun applyTweak(ctx: KeyAggContext, tweak: ByteArray, isXonly: Boolean): KeyAggContext {
        require(tweak.size == 32) { "Tweak must be 32 bytes" }
        
        val qX = intFromBytes(ctx.qXBytes)
        val qY = intFromBytes(ctx.qYBytes)
        val q = Pair(qX, qY)
        val g = if (isXonly && !hasEvenY(qY)) {
            N - BigInteger.ONE
        } else {
            BigInteger.ONE
        }
        
        val t = intFromBytes(tweak)
        require(t < N) { "Tweak must be less than n" }
        
        // Q' = g*Q + t*G
        val gQ = pointMul(q, g)
        val tG = pointMul(Pair(G_X, G_Y), t)
        val qPrime = pointAdd(gQ, tG)
            ?: throw IllegalArgumentException("Tweaked key is point at infinity")
        
        val ctxGacc = intFromBytes(ctx.gaccBytes)
        val ctxTacc = intFromBytes(ctx.taccBytes)
        val gaccPrime = (g * ctxGacc).mod(N)
        val taccPrime = (t + g * ctxTacc).mod(N)
        
        return KeyAggContext(
            qXBytes = bytesFromInt(qPrime.first),
            qYBytes = bytesFromInt(qPrime.second),
            gaccBytes = bytesFromInt(gaccPrime),
            taccBytes = bytesFromInt(taccPrime)
        )
    }
    
    // ========================
    // Nonce Generation
    // ========================
    
    private fun bytesXor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "Arrays must have same length" }
        return ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }
    }
    
    /**
     * Generate nonce hash
     */
    private fun nonceHash(
        rand: ByteArray,
        pk: ByteArray,
        aggpk: ByteArray,
        i: Int,
        msgPrefixed: ByteArray,
        extraIn: ByteArray
    ): BigInteger {
        val buf = rand +
            byteArrayOf(pk.size.toByte()) + pk +
            byteArrayOf(aggpk.size.toByte()) + aggpk +
            msgPrefixed +
            intToBytes4(extraIn.size) + extraIn +
            byteArrayOf(i.toByte())
        
        return intFromBytes(taggedHash("MuSig/nonce", buf))
    }
    
    private fun intToBytes4(n: Int): ByteArray {
        return byteArrayOf(
            (n shr 24).toByte(),
            (n shr 16).toByte(),
            (n shr 8).toByte(),
            n.toByte()
        )
    }
    
    /**
     * Generate nonce pair (secnonce, pubnonce)
     * 
     * @param sk Optional: secret key (32 bytes)
     * @param pk Required: individual public key (33 bytes)
     * @param aggpk Optional: aggregated public key (32 bytes x-only)
     * @param msg Optional: message to sign
     * @param extraIn Optional: extra input for randomness
     * @return Pair of (secnonce: 97 bytes, pubnonce: 66 bytes)
     */
    fun nonceGen(
        sk: ByteArray? = null,
        pk: ByteArray,
        aggpk: ByteArray? = null,
        msg: ByteArray? = null,
        extraIn: ByteArray? = null
    ): Pair<ByteArray, ByteArray> {
        require(sk == null || sk.size == 32) { "Secret key must be 32 bytes" }
        require(pk.size == 33) { "Public key must be 33 bytes" }
        require(aggpk == null || aggpk.size == 32) { "Aggregated pubkey must be 32 bytes" }
        
        // Generate random bytes
        val randPrime = kotlin.random.Random.nextBytes(32)
        
        val rand = if (sk != null) {
            bytesXor(sk, taggedHash("MuSig/aux", randPrime))
        } else {
            randPrime
        }
        
        val effectiveAggpk = aggpk ?: ByteArray(0)
        
        val msgPrefixed = if (msg == null) {
            byteArrayOf(0x00)
        } else {
            byteArrayOf(0x01) + intToBytes8(msg.size.toLong()) + msg
        }
        
        val effectiveExtraIn = extraIn ?: ByteArray(0)
        
        val k1 = nonceHash(rand, pk, effectiveAggpk, 0, msgPrefixed, effectiveExtraIn).mod(N)
        val k2 = nonceHash(rand, pk, effectiveAggpk, 1, msgPrefixed, effectiveExtraIn).mod(N)
        
        require(k1 != BigInteger.ZERO) { "k1 is zero - extremely unlikely" }
        require(k2 != BigInteger.ZERO) { "k2 is zero - extremely unlikely" }
        
        val rs1 = pointMul(Pair(G_X, G_Y), k1)!!
        val rs2 = pointMul(Pair(G_X, G_Y), k2)!!
        
        val pubnonce = cbytes(rs1) + cbytes(rs2)
        val secnonce = bytesFromInt(k1) + bytesFromInt(k2) + pk
        
        return Pair(secnonce, pubnonce)
    }
    
    private fun intToBytes8(n: Long): ByteArray {
        return ByteArray(8) { i -> (n shr (56 - i * 8)).toByte() }
    }
    
    /**
     * Aggregate pubnonces from all signers
     */
    fun nonceAgg(pubnonces: List<ByteArray>): ByteArray {
        require(pubnonces.isNotEmpty()) { "Must have at least one pubnonce" }
        
        var aggnonce = ByteArray(0)
        
        for (j in 1..2) {
            var rj: Pair<BigInteger, BigInteger>? = null
            
            for (i in pubnonces.indices) {
                val slice = pubnonces[i].copyOfRange((j - 1) * 33, j * 33)
                val rij = try {
                    cpoint(slice)
                } catch (e: Exception) {
                    throw InvalidContributionError(i, "pubnonce")
                }
                rj = pointAdd(rj, rij)
            }
            
            // Encode result (or point at infinity as 33 zero bytes)
            aggnonce += if (rj == null) {
                ByteArray(33)
            } else {
                cbytes(rj)
            }
        }
        
        return aggnonce
    }
    
    // ========================
    // Signing
    // ========================
    
    /**
     * Decode compressed point or point at infinity
     */
    private fun cpointExt(x: ByteArray): Pair<BigInteger, BigInteger>? {
        if (x.all { it == 0.toByte() }) return null
        return cpoint(x)
    }
    
    /**
     * Get session values for signing
     */
    private fun getSessionValues(ctx: SessionContext): SessionValues {
        val keyaggCtx = keyAggAndTweak(ctx.pubkeys, ctx.tweaks, ctx.isXonly)
        val qX = intFromBytes(keyaggCtx.qXBytes)
        val qY = intFromBytes(keyaggCtx.qYBytes)
        val q = Pair(qX, qY)
        
        val b = intFromBytes(
            taggedHash("MuSig/noncecoef", ctx.aggnonce + xbytes(q) + ctx.msg)
        ).mod(N)
        
        val r1 = cpointExt(ctx.aggnonce.copyOfRange(0, 33))
        val r2 = cpointExt(ctx.aggnonce.copyOfRange(33, 66))
        
        val rPrime = pointAdd(r1, pointMul(r2, b))
        val r = rPrime ?: Pair(G_X, G_Y)  // Fall back to G if R is infinity
        
        val e = intFromBytes(
            taggedHash("BIP0340/challenge", xbytes(r) + xbytes(q) + ctx.msg)
        ).mod(N)
        
        val gacc = intFromBytes(keyaggCtx.gaccBytes)
        val tacc = intFromBytes(keyaggCtx.taccBytes)
        
        return SessionValues(q, gacc, tacc, b, r, e)
    }
    
    private data class SessionValues(
        val q: Pair<BigInteger, BigInteger>,
        val gacc: BigInteger,
        val tacc: BigInteger,
        val b: BigInteger,
        val r: Pair<BigInteger, BigInteger>,
        val e: BigInteger
    )
    
    private fun keyAggAndTweak(
        pubkeys: List<ByteArray>,
        tweaks: List<ByteArray>,
        isXonly: List<Boolean>
    ): KeyAggContext {
        require(tweaks.size == isXonly.size) { "tweaks and isXonly must have same length" }
        
        var ctx = keyAgg(pubkeys)
        for (i in tweaks.indices) {
            ctx = applyTweak(ctx, tweaks[i], isXonly[i])
        }
        return ctx
    }
    
    /**
     * Create partial signature
     * 
     * @param secnonce Secret nonce (97 bytes) - will be zeroed after use!
     * @param sk Private key (32 bytes)
     * @param sessionCtx Session context
     * @return Partial signature (32 bytes)
     */
    fun sign(secnonce: ByteArray, sk: ByteArray, sessionCtx: SessionContext): ByteArray {
        require(secnonce.size == 97) { "secnonce must be 97 bytes" }
        require(sk.size == 32) { "sk must be 32 bytes" }
        
        val (q, gacc, _, b, r, e) = getSessionValues(sessionCtx)
        
        val k1Prime = intFromBytes(secnonce.copyOfRange(0, 32))
        val k2Prime = intFromBytes(secnonce.copyOfRange(32, 64))
        
        // Zero out secnonce to prevent reuse
        secnonce.fill(0)
        
        require(k1Prime > BigInteger.ZERO && k1Prime < N) { "k1 out of range" }
        require(k2Prime > BigInteger.ZERO && k2Prime < N) { "k2 out of range" }
        
        val k1 = if (hasEvenY(r.second)) k1Prime else N - k1Prime
        val k2 = if (hasEvenY(r.second)) k2Prime else N - k2Prime
        
        val dPrime = intFromBytes(sk)
        require(dPrime > BigInteger.ZERO && dPrime < N) { "Private key out of range" }
        
        val p = pointMul(Pair(G_X, G_Y), dPrime)!!
        val pkStored = secnonce.copyOfRange(64, 97)
        
        val a = keyAggCoeff(sessionCtx.pubkeys, cbytes(p))
        val g = if (hasEvenY(q.second)) BigInteger.ONE else N - BigInteger.ONE
        val d = (g * gacc * dPrime).mod(N)
        
        val s = (k1 + b * k2 + e * a * d).mod(N)
        
        return bytesFromInt(s)
    }
    
    /**
     * Aggregate partial signatures into final Schnorr signature
     */
    fun partialSigAgg(psigs: List<ByteArray>, sessionCtx: SessionContext): ByteArray {
        val (q, _, tacc, _, r, e) = getSessionValues(sessionCtx)
        
        var s = BigInteger.ZERO
        for (i in psigs.indices) {
            val si = intFromBytes(psigs[i])
            if (si >= N) {
                throw InvalidContributionError(i, "psig")
            }
            s = (s + si).mod(N)
        }
        
        val g = if (hasEvenY(q.second)) BigInteger.ONE else N - BigInteger.ONE
        s = (s + e * g * tacc).mod(N)
        
        return xbytes(r) + bytesFromInt(s)
    }
    
    /**
     * Verify a final Schnorr signature (BIP-340)
     */
    fun schnorrVerify(msg: ByteArray, pubkey: ByteArray, sig: ByteArray): Boolean {
        require(msg.size == 32) { "Message must be 32 bytes" }
        require(pubkey.size == 32) { "Public key must be 32 bytes (x-only)" }
        require(sig.size == 64) { "Signature must be 64 bytes" }
        
        val p = liftX(pubkey) ?: return false
        val r = intFromBytes(sig.copyOfRange(0, 32))
        val s = intFromBytes(sig.copyOfRange(32, 64))
        
        if (r >= P || s >= N) return false
        
        val e = intFromBytes(
            taggedHash("BIP0340/challenge", sig.copyOfRange(0, 32) + pubkey + msg)
        ).mod(N)
        
        // R = s*G - e*P
        val sG = pointMul(Pair(G_X, G_Y), s)
        val eP = pointMul(p, e)
        val ePNeg = pointNegate(eP)
        val R = pointAdd(sG, ePNeg)
        
        if (R == null) return false
        if (!hasEvenY(R.second)) return false
        if (R.first != BigInteger.fromByteArray(sig.copyOfRange(0, 32))) return false
        
        return true
    }
    
    // ========================
    // Utility: BigInteger wrapper
    // ========================
    
    private class BigInteger private constructor(val magnitude: KmpBigInteger) : Comparable<BigInteger> {
        companion object {
            val ZERO = BigInteger(KmpBigInteger.ZERO)
            val ONE = BigInteger(KmpBigInteger.ONE)
            
            fun fromHex(hex: String): BigInteger {
                return BigInteger(KmpBigInteger.parseString(hex, 16))
            }
            
            fun fromInt(value: Int): BigInteger {
                return BigInteger(KmpBigInteger.fromInt(value))
            }
            
            fun fromByteArray(bytes: ByteArray): BigInteger {
                return BigInteger(KmpBigInteger.fromByteArray(bytes, Sign.POSITIVE))
            }
        }
        
        operator fun plus(other: BigInteger): BigInteger {
            return BigInteger(magnitude + other.magnitude)
        }
        
        operator fun minus(other: BigInteger): BigInteger {
            return BigInteger(magnitude - other.magnitude)
        }
        
        operator fun times(other: BigInteger): BigInteger {
            return BigInteger(magnitude * other.magnitude)
        }
        
        operator fun div(other: BigInteger): BigInteger {
            return BigInteger(magnitude / other.magnitude)
        }
        
        fun mod(other: BigInteger): BigInteger {
            var result = magnitude.mod(other.magnitude)
            if (result.isNegative) {
                result += other.magnitude
            }
            return BigInteger(result)
        }
        
        fun modPow(exp: BigInteger, mod: BigInteger): BigInteger {
            // Manual square-and-multiply implementation
            var result = KmpBigInteger.ONE
            var base = this.magnitude.mod(mod.magnitude)
            var e = exp.magnitude
            val two = KmpBigInteger.fromInt(2)
            
            while (e > KmpBigInteger.ZERO) {
                if (e.mod(two) == KmpBigInteger.ONE) {
                    result = (result * base).mod(mod.magnitude)
                }
                e = e / two
                base = (base * base).mod(mod.magnitude)
            }
            return BigInteger(result)
        }
        
        fun modInverse(mod: BigInteger): BigInteger {
            return BigInteger(magnitude.modInverse(mod.magnitude))
        }
        
        fun toByteArray(): ByteArray {
            val bytes = magnitude.toByteArray()
            // Ensure unsigned representation (remove leading zero if present)
            return if (bytes.isNotEmpty() && bytes[0] == 0.toByte() && bytes.size > 1) {
                bytes.copyOfRange(1, bytes.size)
            } else {
                bytes
            }
        }
        
        override fun compareTo(other: BigInteger): Int {
            return magnitude.compareTo(other.magnitude)
        }
        
        override fun equals(other: Any?): Boolean {
            if (other !is BigInteger) return false
            return magnitude == other.magnitude
        }
        
        override fun hashCode(): Int = magnitude.hashCode()
    }
}
