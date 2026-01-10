package fr.acinq.secp256k1

import org.kotlincrypto.hash.sha2.SHA256
import com.ionspin.kotlin.bignum.integer.BigInteger as KmpBigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.experimental.xor

internal typealias BigInteger = KmpBigInteger

/**
 * Pure Kotlin implementation of Secp256k1.
 * Bridged from kotlin-crypto-pure.
 */
public object Secp256k1Pure : Secp256k1 {

    private val P: BigInteger = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    private val N: BigInteger = BigInteger.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    private val G_X: BigInteger = BigInteger.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    private val G_Y: BigInteger = BigInteger.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")

    override fun verify(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean {
        return try {
            val (r, s) = if (signature.size == 64) {
                decodeCompact(signature)
            } else {
                decodeDER(signature)
            }
            val z = message.toBigInteger()
            val (pubX, pubY) = decodePublicKey(pubkey)
            val sInv = s.modInverse(N)
            val u1 = (z * sInv) % N
            val u2 = (r * sInv) % N
            val (p1x, p1y) = scalarMultiply(u1, G_X, G_Y)
            val (p2x, p2y) = scalarMultiply(u2, pubX, pubY)
            val (x, _) = pointAdd(p1x, p1y, p2x, p2y)
            r == x % N
        } catch (e: Exception) {
            false
        }
    }

    override fun sign(message: ByteArray, privkey: ByteArray): ByteArray {
        require(message.size == 32)
        require(privkey.size == 32)
        val d = privkey.toBigInteger()
        if (d == BigInteger.ZERO || d >= N) throw IllegalArgumentException("Invalid private key")
        val z = message.toBigInteger()
        val k = generateKDeterministic(privkey, message)
        val (kGx, _) = scalarMultiply(k, G_X, G_Y)
        val r = kGx % N
        if (r == BigInteger.ZERO) throw RuntimeException("r is zero")
        val kInv = k.modInverse(N)
        val s = (kInv * (z + r * d)) % N
        if (s == BigInteger.ZERO) throw RuntimeException("s is zero")
        val nHalf = N / BigInteger(KmpBigInteger.fromInt(2))
        val normalizedS = if (s > nHalf) N - s else s
        return encodeCompact(r, normalizedS)
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        if (data.size != 32 || pub.size != 32 || signature.size != 64) return false
        try {
            val px = pub.toBigInteger()
            if (px >= P) return false
            val P_point = liftX(px)
            val r = signature.sliceArray(0 until 32).toBigInteger()
            if (r >= P) return false
            val s = signature.sliceArray(32 until 64).toBigInteger()
            if (s >= N) return false
            val e = BigInteger.fromByteArray(taggedHash("BIP0340/challenge", signature.sliceArray(0 until 32) + pub + data)) % N
            
            val sG = scalarMultiply(s, G_X, G_Y)
            val negE = N - e
            val negEP = scalarMultiply(negE, P_point.first, P_point.second)
            val R_calc = pointAdd(sG.first, sG.second, negEP.first, negEP.second)
            
            if (isPointAtInfinity(R_calc.first, R_calc.second)) return false
            if (!hasEvenY(R_calc)) return false
            return R_calc.first == r
        } catch (e: Exception) {
            return false
        }
    }

    override fun signSchnorr(data: ByteArray, sec: ByteArray, auxrand32: ByteArray?): ByteArray {
        val auxRand = auxrand32 ?: ByteArray(32)
        val dBig = sec.toBigInteger()
        if (dBig == BigInteger.ZERO || dBig >= N) throw IllegalArgumentException("Invalid private key")
        val P_point = scalarMultiply(dBig, G_X, G_Y)
        val d = if (hasEvenY(P_point)) dBig else N - dBig
        val t = xor(d.toByteArray32(), taggedHash("BIP0340/aux", auxRand))
        val P_bytes = P_point.first.toByteArray32()
        val rand = taggedHash("BIP0340/nonce", t + P_bytes + data)
        val kPrime = BigInteger.fromByteArray(rand) % N
        if (kPrime == BigInteger.ZERO) throw IllegalStateException("kPrime is zero")
        val R_point = scalarMultiply(kPrime, G_X, G_Y)
        val k = if (hasEvenY(R_point)) kPrime else N - kPrime
        val R_bytes = R_point.first.toByteArray32()
        val e = BigInteger.fromByteArray(taggedHash("BIP0340/challenge", R_bytes + P_bytes + data)) % N
        val s = (k + e * d) % N
        return R_bytes + s.toByteArray32()
    }

    override fun signatureNormalize(sig: ByteArray): Pair<ByteArray, Boolean> {
        val (r, s, isCompact) = try {
            if (sig.size == 64) {
                val (r, s) = decodeCompact(sig)
                Triple(r, s, true)
            } else {
                val (r, s) = decodeDER(sig)
                Triple(r, s, false)
            }
        } catch (e: Exception) {
            throw e
        }

        val nHalf = N / BigInteger(KmpBigInteger.fromInt(2))
        return if (s > nHalf) {
            val normalizedS = N - s
            val normalizedSig = if (isCompact) encodeCompact(r, normalizedS) else encodeDER(r, normalizedS)
            Pair(normalizedSig, true)
        } else {
            Pair(sig, false)
        }
    }

    override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        val d = privkey.toBigInteger()
        return d > BigInteger.ZERO && d < N
    }

    override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        val d = privkey.toBigInteger()
        if (d == BigInteger.ZERO || d >= N) throw IllegalArgumentException("Invalid private key")
        val (x, y) = scalarMultiply(d, G_X, G_Y)
        return encodePublicKey(Pair(x, y), false)
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        if (!validatePointOnCurve(x, y)) throw IllegalArgumentException("Invalid public key")
        return encodePublicKey(Pair(x, y), false)
    }

    override fun privKeyNegate(privkey: ByteArray): ByteArray {
        val d = privkey.toBigInteger()
        return (N - d).toByteArray32()
    }

    override fun privKeyTweakAdd(privkey: ByteArray, tweak: ByteArray): ByteArray {
        val d = privkey.toBigInteger()
        val t = tweak.toBigInteger()
        return ((d + t) % N).toByteArray32()
    }

    override fun privKeyTweakMul(privkey: ByteArray, tweak: ByteArray): ByteArray {
        val d = privkey.toBigInteger()
        val t = tweak.toBigInteger()
        return ((d * t) % N).toByteArray32()
    }

    override fun pubKeyNegate(pubkey: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        return encodePublicKey(Pair(x, P - y), false)
    }

    override fun pubKeyTweakAdd(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        val t = tweak.toBigInteger()
        val (tx, ty) = scalarMultiply(t, G_X, G_Y)
        val (rx, ry) = pointAdd(x, y, tx, ty)
        return encodePublicKey(Pair(rx, ry), false)
    }

    override fun pubKeyTweakMul(pubkey: ByteArray, tweak: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        val t = tweak.toBigInteger()
        val (rx, ry) = scalarMultiply(t, x, y)
        return encodePublicKey(Pair(rx, ry), false)
    }

    override fun pubKeyCombine(pubkeys: Array<ByteArray>): ByteArray {
        var res: Pair<BigInteger, BigInteger>? = null
        for (pk in pubkeys) {
            val p = decodePublicKey(pk)
            res = if (res == null) p else pointAdd(res.first, res.second, p.first, p.second)
        }
        return encodePublicKey(res!!, false)
    }

    override fun ecdh(privkey: ByteArray, pubkey: ByteArray): ByteArray {
        val (pubX, pubY) = decodePublicKey(pubkey)
        val d = privkey.toBigInteger()
        val (sharedX, sharedY) = scalarMultiply(d, pubX, pubY)
        val compressed = encodePublicKey(Pair(sharedX, sharedY), true)
        return SHA256().digest(compressed)
    }

    override fun ecdsaRecover(sig: ByteArray, message: ByteArray, recid: Int): ByteArray {
        require(recid in 0..3)
        val (r, s) = decodeCompact(sig)
        val x = r + (if (recid >= 2) N else BigInteger.ZERO)
        if (x >= P) throw IllegalArgumentException("Invalid R")
        val y = decompressY(x, recid % 2 != 0)
        val rInv = r.modInverse(N)
        val z = message.toBigInteger()
        val sR = scalarMultiply(s, x, y)
        val negZ = N - (z % N)
        val negZG = scalarMultiply(negZ, G_X, G_Y)
        val (qx, qy) = pointAdd(sR.first, sR.second, negZG.first, negZG.second)
        val (finalQx, finalQy) = scalarMultiply(rInv, qx, qy)
        return encodePublicKey(Pair(finalQx, finalQy), false)
    }

    override fun compact2der(sig: ByteArray): ByteArray {
        val (r, s) = decodeCompact(sig)
        return encodeDER(r, s)
    }

    override fun cleanup(): Unit {}

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32)
        
        // BIP-327 nonce_gen_internal
        // rand = sk XOR tagged_hash('MuSig/aux', rand_) if sk is not None else rand_
        val rand: ByteArray
        if (privkey != null) {
            val auxHash = taggedHash("MuSig/aux", sessionRandom32)
            rand = ByteArray(32) { i -> (privkey[i].toInt() xor auxHash[i].toInt()).toByte() }
        } else {
            rand = sessionRandom32
        }
        
        // pk is the compressed public key (33 bytes)
        val pk = encodePublicKey(decodePublicKey(pubkey), true)
        
        // aggpk is the x-only aggregated public key (32 bytes) or empty
        val aggpk: ByteArray = if (keyaggCache != null) {
            require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
            // keyaggCache format: magic (4) || Q_x (32) || Q_y (32) || ...
            val Q_uncompressed = keyaggCache.sliceArray(4 until 68)
            val Q = Pair(Q_uncompressed.sliceArray(0 until 32).toBigInteger(), Q_uncompressed.sliceArray(32 until 64).toBigInteger())
            encodePublicKey(Q, true).sliceArray(1 until 33) // X-only
        } else {
            ByteArray(0)
        }
        
        // msg_prefixed: 0x00 if msg is None, else 0x01 || 8-byte len || msg
        val msgPrefixed: ByteArray = if (msg32 != null) {
            byteArrayOf(0x01) + byteArrayOf(0, 0, 0, 0, 0, 0, 0, msg32.size.toByte()) + msg32
        } else {
            byteArrayOf(0x00)
        }
        
        // extra_in
        val extraIn = extraInput32 ?: ByteArray(0)
        
        // nonce_hash for k_1 and k_2
        fun nonceHash(i: Int): BigInteger {
            var buf = ByteArray(0)
            buf += rand
            buf += pk.size.toByte()
            buf += pk
            buf += aggpk.size.toByte()
            buf += aggpk
            buf += msgPrefixed
            buf += byteArrayOf(
                ((extraIn.size shr 24) and 0xFF).toByte(),
                ((extraIn.size shr 16) and 0xFF).toByte(),
                ((extraIn.size shr 8) and 0xFF).toByte(),
                (extraIn.size and 0xFF).toByte()
            )
            buf += extraIn
            buf += i.toByte()
            return BigInteger.fromByteArray(taggedHash("MuSig/nonce", buf)) % N
        }
        
        val k1 = nonceHash(0)
        val k2 = nonceHash(1)
        
        // k_1 == 0 or k_2 == 0 cannot occur except with negligible probability
        require(k1 != BigInteger.ZERO) { "k1 == 0" }
        require(k2 != BigInteger.ZERO) { "k2 == 0" }
        
        val R1 = scalarMultiply(k1, G_X, G_Y)
        val (R2x, R2y) = scalarMultiply(k2, G_X, G_Y)
        
        // Public Nonce: R1 (33) || R2 (33)
        val pubNonce = encodePublicKey(R1, true) + encodePublicKey(Pair(R2x, R2y), true)
        
        // Secret Nonce format (libsecp256k1-zkp compatible): 
        // magic (4) || k1 (32 BE) || k2 (32 BE) || pk_x (32 LE) || pk_y (32 LE) = 132 bytes
        val pkPair = decodePublicKey(pubkey)
        val px = pkPair.first.toByteArray32().reversedArray()
        val py = pkPair.second.toByteArray32().reversedArray()
        
        val magic = byteArrayOf(0x22, 0x0E, 0xDC.toByte(), 0xF1.toByte())
        val k1_be = k1.toByteArray32()
        val k2_be = k2.toByteArray32()
        val secNonce = magic + k1_be + k2_be + px + py
        
        return secNonce + pubNonce
    }

    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg: ByteArray?, keyaggCache: ByteArray?, extraInput: ByteArray?): ByteArray {
        val rand = ByteArray(32)
        // libsecp256k1 pattern for counter: 8-byte BE counter at the start
        var c = nonRepeatingCounter
        for (i in 7 downTo 0) {
            rand[i] = (c and 0xFFu).toByte()
            c = c shr 8
        }
        return musigNonceGen(rand, privkey, pubkeyCreate(privkey), msg, keyaggCache, extraInput)
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        var R1 = Pair(BigInteger.ZERO, BigInteger.ZERO)
        var R2 = Pair(BigInteger.ZERO, BigInteger.ZERO)
        
        for (pn in pubnonces) {
            require(pn.size == 66)
            val p1 = decodePublicKey(pn.sliceArray(0 until 33))
            val p2 = decodePublicKey(pn.sliceArray(33 until 66))
            R1 = pointAdd(R1.first, R1.second, p1.first, p1.second)
            R2 = pointAdd(R2.first, R2.second, p2.first, p2.second)
        }
        
        val encR1 = if (isPointAtInfinity(R1.first, R1.second)) ByteArray(33) else encodePublicKey(R1, true)
        val encR2 = if (isPointAtInfinity(R2.first, R2.second)) ByteArray(33) else encodePublicKey(R2, true)
        return encR1 + encR2
    }
        
    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        val u = pubkeys.size
        // 33-byte compressed encodings
        val pks = pubkeys.map {
            if (it.size == 32) byteArrayOf(2.toByte()) + it else it
        }

        // BIP-327: L = HashKeys(pk1..u) = taggedHash("KeyAgg list", pk1 || ... || pku)
        // Ensure keys are 33-byte compressed encoding for hashing
        val pks_compressed = pks.map { 
            when (it.size) {
                32 -> byteArrayOf(2.toByte()) + it // Assume even Y for X-only input? Or error? Standard takes 33-byte.
                33 -> it
                65 -> {
                    val (x, y) = decodePublicKey(it)
                    encodePublicKey(Pair(x, y), true)
                }
                else -> throw IllegalArgumentException("Invalid public key size: ${it.size}")
            }
        }

        val L_buf = pks_compressed.reduce { acc, bytes -> acc + bytes }
        pks_compressed.forEachIndexed { i, pk -> println("DEBUG KeyAgg: pk${i}_compressed=${Hex.encode(pk)}") }
        val L = taggedHash("KeyAgg list", L_buf)
        println("DEBUG KeyAgg: L=${Hex.encode(L)}")

        val pk1 = pks[0]
        var pk2: ByteArray? = null
        for (i in 1 until u) {
            if (!pks[i].contentEquals(pk1)) {
                pk2 = pks[i]
                break
            }
        }

        var Q: Pair<BigInteger, BigInteger> = Pair(BigInteger.ZERO, BigInteger.ZERO)
        for (i in 0 until u) {
            val pki = pks[i]
            val pki_compressed = if (pki.size == 32) byteArrayOf(2.toByte()) + pki else pki
            
            val a = if (pk2 != null && pki.contentEquals(pk2)) {
                // BIP-327: a_i = 1 for the second distinct public key
                BigInteger.ONE
            } else {
                // BIP-327: a_i = hash_aggcoef(L || pki)
                BigInteger.fromByteArray(taggedHash("KeyAgg coefficient", L + pki_compressed)) % N
            }
            println("DEBUG KeyAgg: i=$i a=${Hex.encode(a.toByteArray32())}")
            
            val (Px, Py) = decodePublicKey(pki)
            val (aPx, aPy) = scalarMultiply(a, Px, Py)
            Q = pointAdd(Q.first, Q.second, aPx, aPy)
        }

        if (isPointAtInfinity(Q.first, Q.second)) throw Secp256k1Exception("aggregated public key is point at infinity")

        // g_acc (index 100) tracks if t_acc is negated. Initialize to 0.
        // Q parity (g) is derived from Q.second in PartialSign.
        val g_acc = 0.toByte()
        
        if (keyaggCache != null) {
            Hex.decode("f4adbbdf").copyInto(keyaggCache, 0)
            encodePublicKey(Q, false).sliceArray(1 until 65).copyInto(keyaggCache, 4)
            BigInteger.ZERO.toByteArray32().copyInto(keyaggCache, 68)
            keyaggCache[100] = g_acc
            L.copyInto(keyaggCache, 101, 0, 32)
            // Store pk2 (if exists) at 134. If non-existent (only 1 key), store 0s.
            if (pk2 != null) {
                pk2.copyInto(keyaggCache, 134, 0, 33)
            } else {
                ByteArray(33).copyInto(keyaggCache, 134)
            }
        }
        println("DEBUG KeyAgg: Q parity is ${if (isOdd(Q.second)) "ODD" else "EVEN"}")

        return encodePublicKey(Q, true).sliceArray(1 until 33)
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        val Q = Pair(keyaggCache.sliceArray(4 until 36).toBigInteger(), keyaggCache.sliceArray(36 until 68).toBigInteger())
        
        val tweak = BigInteger.fromByteArray(tweak32)
        
        if (tweak >= N) throw IllegalArgumentException("Tweak must be less than order N")

        // Apply tweak: Q = Q + t*G
        val (tx, ty) = scalarMultiply(tweak, G_X, G_Y)
        val (QprimeX, QprimeY) = pointAdd(Q.first, Q.second, tx, ty)
        if (isPointAtInfinity(QprimeX, QprimeY)) throw IllegalArgumentException("Tweak results in point at infinity")
        
        var Qprime = Pair(QprimeX, QprimeY)
        
        var currentTweakVal = (keyaggCache.sliceArray(68 until 100).toBigInteger() + tweak) % N
        
        encodePublicKey(Qprime, false).sliceArray(1 until 65).copyInto(keyaggCache, 4)
        currentTweakVal.toByteArray32().copyInto(keyaggCache, 68)
        
        // Return 33 bytes (Compressed) so that PublicKey(bytes) constructor works correctly.
        return encodePublicKey(Qprime, true)
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        var Q = Pair(keyaggCache.sliceArray(4 until 36).toBigInteger(), keyaggCache.sliceArray(36 until 68).toBigInteger())
        
        // Wrapper fromByteArray forces Positive.
        val tweak = BigInteger.fromByteArray(tweak32)
        
        if (tweak >= N) throw IllegalArgumentException("Tweak must be less than order N")

        // If Q has odd Y, negate it (and acc/g) to enforce X-only implicit Y
        if (isOdd(Q.second)) {
            Q = Pair(Q.first, P - Q.second)
            keyaggCache[100] = (keyaggCache[100].toInt() xor 1).toByte()
            val currentTweakVal = keyaggCache.sliceArray(68 until 100).toBigInteger()
            val newTweakVal = (N - currentTweakVal) % N
            newTweakVal.toByteArray32().copyInto(keyaggCache, 68)
        }

        val (tx, ty) = scalarMultiply(tweak, G_X, G_Y)
        var Qprime = pointAdd(Q.first, Q.second, tx, ty)
        if (isPointAtInfinity(Qprime.first, Qprime.second)) throw IllegalArgumentException("Tweak results in point at infinity")
        
        var currentTweakVal = (keyaggCache.sliceArray(68 until 100).toBigInteger() + tweak) % N
        
        if (isOdd(Qprime.second)) {
            Qprime = Pair(Qprime.first, P - Qprime.second)
            keyaggCache[100] = (keyaggCache[100].toInt() xor 1).toByte()
            currentTweakVal = (N - currentTweakVal) % N
        }
        
        encodePublicKey(Qprime, false).sliceArray(1 until 65).copyInto(keyaggCache, 4)
        currentTweakVal.toByteArray32().copyInto(keyaggCache, 68)
        
        // Return 33 bytes (Compressed) so that PublicKey(bytes) constructor works correctly.
        return encodePublicKey(Qprime, true)
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        require(aggnonce.size == 66)
        // require(msg32.size == 32) // Removed check to support arbitrary message sizes as per spec (msg32 is hashed)
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        
        val R1_bytes = aggnonce.sliceArray(0 until 33)
        val R1 = if (R1_bytes.all { it == 0.toByte() }) Pair(BigInteger.ZERO, BigInteger.ZERO) else decodePublicKey(R1_bytes)
        
        val R2_bytes = aggnonce.sliceArray(33 until 66)
        val R2 = if (R2_bytes.all { it == 0.toByte() }) Pair(BigInteger.ZERO, BigInteger.ZERO) else decodePublicKey(R2_bytes)
        
        // keyaggCache format: magic (4) || Q (64) || t_acc (32) || g_acc (1) || ...
        val Q_bytes = keyaggCache.sliceArray(4 until 68)
        val Q = Pair(Q_bytes.sliceArray(0 until 32).toBigInteger(), Q_bytes.sliceArray(32 until 64).toBigInteger())
        val Q_x_compressed = encodePublicKey(Q, true) // 33-byte Q
        
        // Compute b = taggedHash("MuSig/noncecoef", aggnonce + Q + m)
        val b = BigInteger.fromByteArray(taggedHash("MuSig/noncecoef", aggnonce + Q_x_compressed + msg32)) % N
        println("DEBUG NonceProcess: b=${Hex.encode(b.toByteArray32())}")

        // R = R1 + b*R2
        val (R2bx, R2by) = scalarMultiply(b, R2.first, R2.second)
        val (Rx, Ry) = pointAdd(R1.first, R1.second, R2bx, R2by)
        println("DEBUG NonceProcess: R_raw=(${Hex.encode(Rx.toByteArray32())},${Hex.encode(Ry.toByteArray32())}) Parity=${if (isOdd(Ry)) "ODD" else "EVEN"}")

        var R = Pair(Rx, Ry)
        var negate_nonces = false
        if (isOdd(Ry)) {
            R = Pair(Rx, P - Ry)
            negate_nonces = true
            println("DEBUG NonceProcess: Negating nonces (R was Odd)")
        } else {
             println("DEBUG NonceProcess: No negation (R was Even)")
        }
        val R_final = R
        println("DEBUG NonceProcess: R_final=(${Hex.encode(R_final.first.toByteArray32())},${Hex.encode(R_final.second.toByteArray32())})")
        
        // e = H(R_x || Q_x || m)
        val Rx_bytes = if (isPointAtInfinity(R_final.first, R_final.second)) ByteArray(32) else encodePublicKey(R_final, true).sliceArray(1 until 33)
        // Fix: e calculation uses XOnly Q (32 bytes), not Compressed Q (33 bytes)
        val Qx_bytes = Q_x_compressed.sliceArray(1 until 33)
        // BigInteger.fromByteArray in this file forces Positive interpretation.
        val e = (BigInteger.fromByteArray(taggedHash("BIP0340/challenge", Rx_bytes + Qx_bytes + msg32)) % N)
        
        
        val session = ByteArray(Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        session[0] = if (negate_nonces) 1.toByte() else 0.toByte()
        b.toByteArray32().copyInto(session, 1, 0, 32)
        e.toByteArray32().copyInto(session, 33, 0, 32)
        // Copy t_acc (65..97) and g_acc (97) from cache
        keyaggCache.copyInto(session, 65, 68, 101)
        // Store R_final_x (32 bytes) at 98 for partialSigAgg
        Rx_bytes.copyInto(session, 98, 0, 32)
        
        return session
    }

    override fun musigPartialSign(
        secnonce: ByteArray,
        privkey: ByteArray,
        keyaggCache: ByteArray,
        session: ByteArray
    ): ByteArray {
        require(secnonce.size == Secp256k1.MUSIG2_SECRET_NONCE_SIZE)
        require(privkey.size == 32)
        require(keyaggCache.size == Secp256k1.MUSIG2_PUBLIC_KEYAGG_CACHE_SIZE)
        require(session.size == Secp256k1.MUSIG2_PUBLIC_SESSION_SIZE)
        
        // Wrapper fromByteArray forces Positive.
        val sk = BigInteger.fromByteArray(privkey)
        val L = keyaggCache.sliceArray(101 until 133)
        
        val Pi = decodePublicKey(pubkeyCreate(privkey))
        val pki = encodePublicKey(Pi, true)
        
        // pk2 (second distinct key) is stored at 134. If matching, a=1.
        val pk2 = keyaggCache.sliceArray(134 until 167)
        val isPk2 = !pk2.contentEquals(ByteArray(33)) && pki.contentEquals(pk2)
        
        val a = if (isPk2) {
            BigInteger.ONE
        } else {
            BigInteger.fromByteArray(taggedHash("KeyAgg coefficient", L + pki)) % N
        }
        
        // Derive g from Q in cache? NO. Use g_acc from cache (index 100).
        // val Qbytes = keyaggCache.sliceArray(4 until 68)
        // val Q = Pair(Qbytes.sliceArray(0 until 32).toBigInteger(), Qbytes.sliceArray(32 until 64).toBigInteger())
        // val g_acc = if (isOdd(Q.second)) N - BigInteger.ONE else BigInteger.ONE
        
        val g_acc = if (keyaggCache[100] == 1.toByte()) N - BigInteger.ONE else BigInteger.ONE
        println("DEBUG PartialSign: g_acc from cache[100]=${keyaggCache[100]} => ${if(g_acc == BigInteger.ONE) "1 (Even)" else "-1 (Odd)"}")
        
        val k1 = BigInteger.fromByteArray(secnonce.sliceArray(4 until 36)) // Unsigned
        val k2 = BigInteger.fromByteArray(secnonce.sliceArray(36 until 68)) // Unsigned
        val b = BigInteger.fromByteArray(session.sliceArray(1 until 33)) // Unsigned
        val e = BigInteger.fromByteArray(session.sliceArray(33 until 65)) // Unsigned
        
        val gv = if (session[0] == 1.toByte()) N - BigInteger.ONE else BigInteger.ONE
        
        println("DEBUG PartialSign:")
        println("  k1: ${Hex.encode(k1.toByteArray32())}")
        println("  k2: ${Hex.encode(k2.toByteArray32())}")
        println("  b: ${Hex.encode(b.toByteArray32())}")
        println("  e: ${Hex.encode(e.toByteArray32())}")
        println("  a: ${Hex.encode(a.toByteArray32())}")
        println("  g_acc: ${Hex.encode(g_acc.toByteArray32())}")
        println("  gv: ${Hex.encode(gv.toByteArray32())}")
        
        val s_raw = (gv * (k1 + b * k2) + e * a * g_acc * sk) % N
        val s: BigInteger = if (s_raw < BigInteger.ZERO) s_raw + N else s_raw
        println("  s: ${Hex.encode(s.toByteArray32())}")
        
        return s.toByteArray32()
    }

    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        val s = BigInteger.fromByteArray(psig)
        if (s >= N) return 0
        
        val L = keyaggCache.sliceArray(101 until 133)
        val pk1 = keyaggCache.sliceArray(134 until 167)
        val pki = if (pubkey.size == 32) byteArrayOf(2.toByte()) + pubkey else pubkey

        val a = if (pki.contentEquals(pk1)) {
            BigInteger.ONE
        } else {
            BigInteger.fromByteArray(taggedHash("KeyAgg coefficient", L + pki)) % N
        }
        
        val g_acc = if ((keyaggCache[100].toInt() and 1) == 1) N - BigInteger.ONE else BigInteger.ONE
        
        val b = session.sliceArray(1 until 33).toBigInteger()
        val e = session.sliceArray(33 until 65).toBigInteger()
        
        val R1 = decodePublicKey(pubnonce.sliceArray(0 until 33))
        val R2 = decodePublicKey(pubnonce.sliceArray(33 until 66))
        val (bR2x, bR2y) = scalarMultiply(b, R2.first, R2.second)
        val (Rx, Ry) = pointAdd(R1.first, R1.second, bR2x, bR2y)
        
        val gv = if (session[0] == 1.toByte()) N - BigInteger.ONE else BigInteger.ONE
        val (gvRx, gvRy) = scalarMultiply(gv, Rx, Ry)
        
        val Pi = decodePublicKey(pki)
        val eaxPiy_scalar_raw = (e * a * g_acc) % N
        val eaxPiy_scalar = if (eaxPiy_scalar_raw < BigInteger.ZERO) eaxPiy_scalar_raw + N else eaxPiy_scalar_raw
        val (eaxPix, eaxPiy) = scalarMultiply(eaxPiy_scalar, Pi.first, Pi.second)
        val (targetX, targetY) = pointAdd(gvRx, gvRy, eaxPix, eaxPiy)
        
        val (sGx, sGy) = scalarMultiply(s, G_X, G_Y)
        
        return if (sGx == targetX && sGy == targetY) 1 else 0
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray {
        var s_sum = BigInteger.ZERO
        for (sig in psigs) {
            require(sig.size == 32)
            val bi = sig.toBigInteger()
            if (bi >= N) throw IllegalArgumentException("Partial signature out of range")
            s_sum = (s_sum + bi) % N
        }
        
        val e = session.sliceArray(33 until 65).toBigInteger()
        val t_acc = session.sliceArray(65 until 97).toBigInteger()
        
        println("DEBUG PartialSigAgg:")
        println("  s_sum: ${Hex.encode(s_sum.toByteArray32())}")
        println("  e: ${Hex.encode(e.toByteArray32())}")
        println("  t_acc: ${Hex.encode(t_acc.toByteArray32())}")
        
        // g stored at 97 (1 byte)
        // g stored at 97 (1 byte)
        // g stored at 97 (1 byte)
        val g = if (session[97] == 1.toByte()) N - BigInteger.ONE else BigInteger.ONE
        println("  g: ${Hex.encode(g.toByteArray32())}")
        
        // s_agg = sum(s_i) + e * t_acc (g factor is implicit in t_acc accumulation relative to Q)
        val s_agg = (s_sum + (e * t_acc)) % N
        println("  s_agg: ${Hex.encode(s_agg.toByteArray32())}")
        
        val R_final_x = session.sliceArray(98 until 130)
        return R_final_x + s_agg.toByteArray32()
    }

    private fun pointAdd(x1: BigInteger, y1: BigInteger, x2: BigInteger, y2: BigInteger): Pair<BigInteger, BigInteger> {
        if (isPointAtInfinity(x1, y1)) return Pair(x2, y2)
        if (isPointAtInfinity(x2, y2)) return Pair(x1, y1)
        if (x1 == x2 && (y1 + y2) % P == BigInteger.ZERO) return Pair(BigInteger.ZERO, BigInteger.ZERO)
        
        val three = BigInteger(KmpBigInteger.fromInt(3))
        val two = BigInteger(KmpBigInteger.fromInt(2))
        
        val s = if (x1 == x2 && y1 == y2) {
            val num = (three * x1 * x1) % P
            val den = (two * y1).modInverse(P)
            (num * den) % P
        } else {
            val num = (y2 - y1) % P
            val den = (x2 - x1).modInverse(P)
            (num * den) % P
        }
        
        val x3 = (s * s - x1 - x2) % P
        val y3 = (s * (x1 - x3) - y1) % P
        return Pair(x3, y3)
    }

    private fun scalarMultiply(k: BigInteger, x: BigInteger, y: BigInteger): Pair<BigInteger, BigInteger> {
        var res = Pair(BigInteger.ZERO, BigInteger.ZERO)
        var temp = Pair(x, y)
        var scalar = k % N
        while (scalar > BigInteger.ZERO) {
            if (scalar % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ONE) res = pointAdd(res.first, res.second, temp.first, temp.second)
            temp = pointAdd(temp.first, temp.second, temp.first, temp.second)
            scalar /= BigInteger(KmpBigInteger.fromInt(2))
        }
        return res
    }

    private fun generateKDeterministic(privkey: ByteArray, messageHash: ByteArray): BigInteger {
        var v = ByteArray(32) { 1 }
        var k = ByteArray(32) { 0 }
        k = hmacSha256(k, v + byteArrayOf(0) + privkey + messageHash)
        v = hmacSha256(k, v)
        k = hmacSha256(k, v + byteArrayOf(1) + privkey + messageHash)
        v = hmacSha256(k, v)
        while (true) {
            v = hmacSha256(k, v)
            val candidate = BigInteger.fromByteArray(v)
            if (candidate >= BigInteger.ONE && candidate < N) return candidate
            k = hmacSha256(k, v + byteArrayOf(0))
            v = hmacSha256(k, v)
        }
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val blockSize = 64
        val opad = 0x5c.toByte()
        val ipad = 0x36.toByte()
        var k = if (key.size > blockSize) SHA256().digest(key) else key
        if (k.size < blockSize) k = k + ByteArray(blockSize - k.size)
        val oKeyPad = ByteArray(blockSize) { i -> k[i] xor opad }
        val iKeyPad = ByteArray(blockSize) { i -> k[i] xor ipad }
        return SHA256().digest(oKeyPad + SHA256().digest(iKeyPad + data))
    }

    private fun encodeCompact(r: BigInteger, s: BigInteger): ByteArray = r.toByteArray32() + s.toByteArray32()

    private fun decodeCompact(signature: ByteArray): Pair<BigInteger, BigInteger> {
        require(signature.size == 64)
        val r = signature.sliceArray(0 until 32).toBigInteger()
        val s = signature.sliceArray(32 until 64).toBigInteger()
        require(r >= BigInteger.ONE && r < N)
        require(s >= BigInteger.ONE && s < N)
        return Pair(r, s)
    }

    private fun decodeDER(signature: ByteArray): Pair<BigInteger, BigInteger> {
        var i = 0
        require(signature[i++] == 0x30.toByte())
        i++ // skip length
        require(signature[i++] == 0x02.toByte())
        val rLen = signature[i++].toInt() and 0xFF
        val r = signature.sliceArray(i until i + rLen).toBigInteger()
        i += rLen
        require(signature[i++] == 0x02.toByte())
        val sLen = signature[i++].toInt() and 0xFF
        val s = signature.sliceArray(i until i + sLen).toBigInteger()
        return Pair(r, s)
    }

    private fun encodeDER(r: BigInteger, s: BigInteger): ByteArray {
        val rb = r.toByteArrayDER()
        val sb = s.toByteArrayDER()
        return byteArrayOf(0x30, (rb.size + sb.size + 4).toByte(), 0x02, rb.size.toByte()) + rb + byteArrayOf(0x02, sb.size.toByte()) + sb
    }

    private fun decodePublicKey(pk: ByteArray): Pair<BigInteger, BigInteger> {
        return when (pk[0]) {
            0x04.toByte() -> {
                require(pk.size == 65)
                val x = BigInteger.fromByteArray(byteArrayOf(0) + pk.sliceArray(1 until 33))
                val y = BigInteger.fromByteArray(byteArrayOf(0) + pk.sliceArray(33 until 65))
                if (x >= P || x < BigInteger.ZERO || y >= P || y < BigInteger.ZERO) throw IllegalArgumentException("Invalid public key: coordinate not in [0, P-1]")
                if (!validatePointOnCurve(x, y)) throw IllegalArgumentException("Invalid public key: point not on curve")
                Pair(x, y)
            }
            0x02.toByte(), 0x03.toByte() -> {
                require(pk.size == 33)
                val x = BigInteger.fromByteArray(byteArrayOf(0) + pk.sliceArray(1 until 33))
                if (x >= P || x < BigInteger.ZERO) throw IllegalArgumentException("Invalid public key: coordinate not in [0, P-1]")
                val y = decompressY(x, pk[0] == 0x03.toByte())
                Pair(x, y)
            }
            else -> throw IllegalArgumentException("Invalid public key format")
        }
    }

    private fun encodePublicKey(p: Pair<BigInteger, BigInteger>, compressed: Boolean): ByteArray {
        if (isPointAtInfinity(p.first, p.second)) throw IllegalArgumentException("Point at infinity")
        return if (compressed) {
            val prefix = if (p.second % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO) 0x02 else 0x03
            byteArrayOf(prefix.toByte()) + p.first.toByteArray32()
        } else {
            byteArrayOf(0x04) + p.first.toByteArray32() + p.second.toByteArray32()
        }
    }

    private fun decompressY(x: BigInteger, isOdd: Boolean): BigInteger {
        val alpha = (x * x * x + BigInteger(KmpBigInteger.fromInt(7))) % P
        val beta = alpha.modPow((P + BigInteger.ONE) / BigInteger(KmpBigInteger.fromInt(4)), P)
        // Check if beta is actually a square root
        if ((beta * beta) % P != alpha) {
            throw IllegalArgumentException("Invalid compressed public key: point not on curve")
        }
        return if ((beta % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ONE) == isOdd) beta else P - beta
    }

    private fun isPointAtInfinity(x: BigInteger, y: BigInteger): Boolean = x == BigInteger.ZERO && y == BigInteger.ZERO

    private fun hasEvenY(p: Pair<BigInteger, BigInteger>): Boolean = p.second % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO
    
    private fun isOdd(bi: BigInteger): Boolean = bi.magnitude % KmpBigInteger.TWO != KmpBigInteger.ZERO

    private fun liftX(x: BigInteger): Pair<BigInteger, BigInteger> = Pair(x, decompressY(x, false))

    private fun validatePointOnCurve(x: BigInteger, y: BigInteger): Boolean = (y * y) % P == (x * x * x + BigInteger(KmpBigInteger.fromInt(7))) % P

    private fun taggedHash(tag: String, data: ByteArray): ByteArray {
        val head = SHA256().digest(tag.encodeToByteArray())
        return SHA256().digest(head + head + data)
    }

    private fun xor(a: ByteArray, b: ByteArray): ByteArray = ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }

    private class BigInteger(internal val magnitude: KmpBigInteger) {
        companion object {
            val ZERO: BigInteger = BigInteger(KmpBigInteger.ZERO)
            val ONE: BigInteger = BigInteger(KmpBigInteger.ONE)
            fun fromByteArray(b: ByteArray): BigInteger = BigInteger(KmpBigInteger.fromByteArray(b, Sign.POSITIVE))
            fun fromHex(h: String): BigInteger = BigInteger(KmpBigInteger.parseString(h, 16))
        }

        operator fun plus(o: BigInteger): BigInteger = BigInteger(magnitude + o.magnitude)
        operator fun minus(o: BigInteger): BigInteger = BigInteger(magnitude - o.magnitude)
        operator fun times(o: BigInteger): BigInteger = BigInteger(magnitude * o.magnitude)
        operator fun div(o: BigInteger): BigInteger = BigInteger(magnitude / o.magnitude)
        operator fun rem(o: BigInteger): BigInteger {
            val r = magnitude % o.magnitude
            return if (r < KmpBigInteger.ZERO) BigInteger(r + o.magnitude) else BigInteger(r)
        }
        operator fun compareTo(o: BigInteger): Int = magnitude.compareTo(o.magnitude)
        override fun equals(o: Any?): Boolean = o is BigInteger && magnitude == o.magnitude
        override fun hashCode(): Int = magnitude.hashCode()

        fun modInverse(m: BigInteger): BigInteger {
            var a = magnitude % m.magnitude
            if (a < KmpBigInteger.ZERO) a += m.magnitude
            var m0 = m.magnitude
            var x0 = KmpBigInteger.ZERO
            var x1 = KmpBigInteger.ONE
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

        fun modPow(e: BigInteger, m: BigInteger): BigInteger {
            var res = KmpBigInteger.ONE
            var b = magnitude % m.magnitude
            var exp = e.magnitude
            while (exp > KmpBigInteger.ZERO) {
                if (exp % KmpBigInteger.TWO == KmpBigInteger.ONE) res = (res * b) % m.magnitude
                b = (b * b) % m.magnitude
                exp /= KmpBigInteger.TWO
            }
            return BigInteger(res)
        }

        fun toByteArray32(): ByteArray {
            val b = magnitude.toByteArray()
            val clean = if (b.size > 32 && b[0] == 0.toByte()) b.sliceArray(1 until b.size) else b
            val res = ByteArray(32)
            clean.copyInto(res, maxOf(0, 32 - clean.size), maxOf(0, clean.size - 32))
            return res
        }

        fun toByteArrayDER(): ByteArray {
            val b = magnitude.toByteArray()
            if (b.isEmpty()) return byteArrayOf(0)
            if ((b[0].toInt() and 0x80) != 0) return byteArrayOf(0) + b
            var start = 0
            while (start < b.size - 1 && b[start] == 0.toByte() && (b[start + 1].toInt() and 0x80) == 0) {
                start++
            }
            return b.sliceArray(start until b.size)
        }
    }

    private fun ByteArray.toBigInteger(): BigInteger = BigInteger.fromByteArray(this)
    private fun ByteArray.toHex(): String = this.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }
}
