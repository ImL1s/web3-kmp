package fr.acinq.secp256k1

import org.kotlincrypto.hash.sha2.SHA256
import com.ionspin.kotlin.bignum.integer.BigInteger as KmpBI
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.experimental.xor

/**
 * Pure Kotlin implementation of Secp256k1.
 * Bridged from kotlin-crypto-pure.
 */
public object Secp256k1Pure : Secp256k1 {

    private val P: PureBI = PureBI.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
    private val N: PureBI = PureBI.fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
    private val G_X: PureBI = PureBI.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    private val G_Y: PureBI = PureBI.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")

    override fun verify(signature: ByteArray, data: ByteArray, pubkey: ByteArray): Boolean {
        if (signature.size != 64 && (signature.size < 70 || signature.size > 73)) throw IllegalArgumentException("Invalid signature size")
        if (pubkey.size != 33 && pubkey.size != 65) throw IllegalArgumentException("Invalid public key")
        return try {
            val (r, s) = if (signature.size == 64) {
                decodeCompact(signature)
            } else {
                decodeDER(signature)
            }
            val z = data.toBigInteger()
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
        if (d == PureBI.ZERO || d >= N) throw Secp256k1Exception("Invalid private key")
        val z = message.toBigInteger()
        val k = generateKDeterministic(privkey, message)
        val (kGx, _) = scalarMultiply(k, G_X, G_Y)
        val r = kGx % N
        if (r == PureBI.ZERO) throw Secp256k1Exception("r is zero")
        val kInv = k.modInverse(N)
        val s = (kInv * (z + r * d)) % N
        if (s == PureBI.ZERO) throw Secp256k1Exception("s is zero")
        val nHalf = N / PureBI(KmpBI.fromInt(2))
        val normalizedS = if (s > nHalf) N - s else s
        return encodeCompact(r, normalizedS)
    }

    override fun verifySchnorr(signature: ByteArray, data: ByteArray, pub: ByteArray): Boolean {
        if (signature.size != 64) return false
        if (pub.size != 32) return false
        try {
            val px = pub.toBigInteger()
            if (px >= P) return false
            val P_point = liftX(px)
            val r = signature.sliceArray(0 until 32).toBigInteger()
            if (r >= P) return false
            val s = signature.sliceArray(32 until 64).toBigInteger()
            if (s >= N) return false
            val e = PureBI.fromByteArray(taggedHash("BIP0340/challenge", signature.sliceArray(0 until 32) + pub + data)) % N
            
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
        if (data.size != 32) throw IllegalArgumentException("Validation failed: message must be 32 bytes")
        if (sec.size != 32) throw IllegalArgumentException("Validation failed: private key must be 32 bytes")
        val auxRand = auxrand32 ?: ByteArray(32)
        val dBig = sec.toBigInteger()
        if (dBig == PureBI.ZERO || dBig >= N) throw Secp256k1Exception("Invalid private key")
        val P_point = scalarMultiply(dBig, G_X, G_Y)
        val d = if (hasEvenY(P_point)) dBig else N - dBig
        val t = xor(d.toByteArray32(), taggedHash("BIP0340/aux", auxRand))
        val P_bytes = P_point.first.toByteArray32()
        val rand = taggedHash("BIP0340/nonce", t + P_bytes + data)
        val kPrime = PureBI.fromByteArray(rand) % N
        if (kPrime == PureBI.ZERO) throw IllegalStateException("kPrime is zero")
        val R_point = scalarMultiply(kPrime, G_X, G_Y)
        val k = if (hasEvenY(R_point)) kPrime else N - kPrime
        val R_bytes = R_point.first.toByteArray32()
        val e = PureBI.fromByteArray(taggedHash("BIP0340/challenge", R_bytes + P_bytes + data)) % N
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

        val nHalf = N / PureBI(KmpBI.fromInt(2))
        return if (s > nHalf) {
            val normalizedS = N - s
            val normalizedSig = encodeCompact(r, normalizedS)
            Pair(normalizedSig, true)
        } else {
            val normalizedSig = encodeCompact(r, s)
            Pair(normalizedSig, false)
        }
    }

    override fun secKeyVerify(privkey: ByteArray): Boolean {
        if (privkey.size != 32) return false
        val d = privkey.toBigInteger()
        return d > PureBI.ZERO && d < N
    }

    override fun pubkeyCreate(privkey: ByteArray): ByteArray {
        val d = privkey.toBigInteger()
        if (d == PureBI.ZERO || d >= N) throw Secp256k1Exception("Invalid private key")
        val (x, y) = scalarMultiply(d, G_X, G_Y)
        return encodePublicKey(Pair(x, y), false)
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        if (!validatePointOnCurve(x, y)) throw Secp256k1Exception("Invalid public key")
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
        if (pubkeys.isEmpty()) throw IllegalArgumentException("Validation failed: pubkeys must not be empty")
        var res: Pair<PureBI, PureBI>? = null
        for (pk in pubkeys) {
            val p = try {
                 decodePublicKey(pk)
            } catch (e: Exception) {
                 throw Secp256k1Exception("Invalid public key")
            }
            res = if (res == null) p else pointAdd(res.first, res.second, p.first, p.second)
        }
        // Check if result is point at infinity (invalid for public key)
        if (isPointAtInfinity(res!!.first, res.second)) {
            throw Secp256k1Exception("Result is point at infinity")
        }
        return encodePublicKey(res, false)
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
        val x = r + (if (recid >= 2) N else PureBI.ZERO)
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

    // --- MuSig2 Functions ---

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray {
        require(sessionRandom32.size == 32)
        val pk = decodePublicKey(pubkey)
        val pk_compressed = encodePublicKey(pk, true)

        val rand = if (privkey != null) {
            // BIP-327: rand = sk XOR TaggedHash("MuSig/aux", session_id)
            xor(privkey, taggedHash("MuSig/aux", sessionRandom32))
        } else {
            sessionRandom32
        }

        val aggpk = if (keyaggCache != null) {
            require(keyaggCache.size == 197)
            keyaggCache.sliceArray(4 until 36)
        } else {
            ByteArray(0)
        }

        val msgPrefixed = if (msg32 != null) {
            byteArrayOf(1) + (msg32.size.toLong().let { len ->
                byteArrayOf(
                    (len shr 56).toByte(), (len shr 48).toByte(), (len shr 40).toByte(), (len shr 32).toByte(),
                    (len shr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()
                )
            }) + msg32
        } else {
            byteArrayOf(0)
        }

        val extraIn = extraInput32 ?: ByteArray(0)
        val extraInPrefixed = (extraIn.size.toLong().let { len ->
            byteArrayOf(
                (len shr 24).toByte(), (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()
            )
        }) + extraIn

        fun nonceHash(i: Int): PureBI {
            // BIP-327: k_i = TaggedHash("MuSig/nonce", rand || 33 || pk || aggpk_len || aggpk || msg_prefixed || extra_len || extra || i)
            val aggpk_len = if (aggpk.isEmpty()) byteArrayOf(0) else byteArrayOf(32)
            val buf = rand + 
                      byteArrayOf(33.toByte()) + pk_compressed + 
                      aggpk_len + aggpk + 
                      msgPrefixed + extraInPrefixed + byteArrayOf(i.toByte())
            return PureBI.fromByteArray(taggedHash("MuSig/nonce", buf)) % N
        }

        val k1 = nonceHash(0)
        val k2 = nonceHash(1)
        if (k1 == PureBI.ZERO || k2 == PureBI.ZERO) throw IllegalStateException("k1 or k2 is zero")

        val R1 = scalarMultiply(k1, G_X, G_Y)
        val R2 = scalarMultiply(k2, G_X, G_Y)

        val pubNonce = encodePublicKey(R1, true) + encodePublicKey(R2, true)
        
        // secnonce: magic(4) + k1(32) + k2(32) + pkX(32) + pkY(32)
        // Note: pkX and pkY are stored little-endian in our SecretNonce format
        val pkX_le = pk.first.toByteArray32().reversedArray()
        val pkY_le = pk.second.toByteArray32().reversedArray()
        val secNonce = byteArrayOf(0x22, 0x0E, 0xDC.toByte(), 0xF1.toByte()) + k1.toByteArray32() + k2.toByteArray32() + pkX_le + pkY_le
        
        return secNonce + pubNonce
    }

    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg: ByteArray?, keyaggCache: ByteArray?, extraInput: ByteArray?): ByteArray {
        val sessionRandom = ByteArray(32)
        for (i in 0 until 8) sessionRandom[i] = (nonRepeatingCounter shr (56 - i * 8)).toByte()
        return musigNonceGen(sessionRandom, privkey, pubkeyCreate(privkey), msg, keyaggCache, extraInput)
    }

    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray {
        var R1 = Pair(PureBI.ZERO, PureBI.ZERO)
        var R2 = Pair(PureBI.ZERO, PureBI.ZERO)
        for (pn in pubnonces) {
            require(pn.size == 66)
            val p1 = decodePublicKey(pn.sliceArray(0 until 33))
            val p2 = decodePublicKey(pn.sliceArray(33 until 66))
            R1 = pointAdd(R1.first, R1.second, p1.first, p1.second)
            R2 = pointAdd(R2.first, R2.second, p2.first, p2.second)
        }
        return encodePublicKey(R1, true) + encodePublicKey(R2, true)
    }

    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        val u = pubkeys.size
        // BIP-327: Public keys are sorted lexicographically by the caller for MuSig2.
        // The KeyAgg algorithm itself is order-dependent.
        // BIP-327: Normalize all public keys to compressed format (33 bytes) for consistent hashing
        val pks = pubkeys.map { encodePublicKey(decodePublicKey(it), true) }
        val L = taggedHash("KeyAgg list", pks.reduce { acc, bytes -> acc + bytes })
        
        val pk1 = pks[0]
        var pk2: ByteArray? = null
        for (i in 1 until u) {
            if (!pks[i].contentEquals(pk1)) {
                pk2 = pks[i]
                break
            }
        }


        
        var Q = Pair(PureBI.ZERO, PureBI.ZERO)
        for (i in 0 until u) {
            val a = if (pk2 != null && pks[i].contentEquals(pk2)) {
                PureBI.ONE
            } else {
                PureBI.fromByteArray(taggedHash("KeyAgg coefficient", L + pks[i])) % N
            }

            
            val P_pt = decodePublicKey(pks[i])
            val aP = scalarMultiply(a, P_pt.first, P_pt.second)
            Q = pointAdd(Q.first, Q.second, aP.first, aP.second)
        }

        if (isPointAtInfinity(Q.first, Q.second)) throw Secp256k1Exception("Aggregated PK is infinity")

        val parity_acc = 0.toByte()
        val Q_xonly = encodePublicKey(Q, true).sliceArray(1 until 33)

        if (keyaggCache != null) {
            require(keyaggCache.size == 197)
            byteArrayOf(0xf4.toByte(), 0xad.toByte(), 0xbb.toByte(), 0xdf.toByte()).copyInto(keyaggCache, 0)
            // Note: internal Q point stored in cache
            val Q_rawX = Q.first.toByteArray32()
            val Q_rawY = Q.second.toByteArray32()
            Q_rawX.copyInto(keyaggCache, 4)
            Q_rawY.copyInto(keyaggCache, 36)
            
            val pk2_X = if (pk2 != null) pk2.sliceArray(1 until 33) else ByteArray(32)
            pk2_X.copyInto(keyaggCache, 68)
            L.copyInto(keyaggCache, 132)
            keyaggCache[164] = parity_acc
            PureBI.ZERO.toByteArray32().copyInto(keyaggCache, 165)
        }
        return Q_xonly
    }

    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == 197)
        var Q = Pair(PureBI.fromByteArray(keyaggCache.sliceArray(4 until 36)), PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68)))
        val t = PureBI.fromByteArray(tweak32)
        if (t >= N) throw IllegalArgumentException("Tweak >= N")

        // Plain tweak: Q' = Q + tG, gacc' = gacc, tacc' = tacc + t
        val tG = scalarMultiply(t, G_X, G_Y)
        Q = pointAdd(Q.first, Q.second, tG.first, tG.second)
        if (isPointAtInfinity(Q.first, Q.second)) throw IllegalArgumentException("Result is infinity")
        
        val t_acc = (PureBI.fromByteArray(keyaggCache.sliceArray(165 until 197)) + t) % N
        
        val Q_raw = encodePublicKey(Q, false).sliceArray(1 until 65)
        Q_raw.copyInto(keyaggCache, 4)
        t_acc.toByteArray32().copyInto(keyaggCache, 165)
        
        return encodePublicKey(Q, true)
    }

    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray {
        require(keyaggCache.size == 197)
        var Q = Pair(PureBI.fromByteArray(keyaggCache.sliceArray(4 until 36)), PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68)))
        val t = PureBI.fromByteArray(tweak32)
        if (t >= N) throw IllegalArgumentException("Tweak >= N")

        var t_acc = PureBI.fromByteArray(keyaggCache.sliceArray(165 until 197))
        var parity_acc = keyaggCache[164].toInt() and 1

        // BIP-327: If is_xonly and Q is odd, negate Q, negate gacc, negate tacc
        if (isOdd(Q.second)) {
            Q = Pair(Q.first, P - Q.second)
            parity_acc = parity_acc xor 1
            t_acc = (N - t_acc) % N
        }

        val tG = scalarMultiply(t, G_X, G_Y)
        Q = pointAdd(Q.first, Q.second, tG.first, tG.second)
        if (isPointAtInfinity(Q.first, Q.second)) throw IllegalArgumentException("Result is infinity")
        
        t_acc = (t_acc + t) % N
        
        val Q_raw = encodePublicKey(Q, false).sliceArray(1 until 65)
        Q_raw.copyInto(keyaggCache, 4)
        keyaggCache[164] = parity_acc.toByte()
        t_acc.toByteArray32().copyInto(keyaggCache, 165)
        
        return encodePublicKey(Q, true)
    }

    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray {
        val aggnonce_pt1 = decodePublicKey(aggnonce.sliceArray(0 until 33))
        val aggnonce_pt2 = decodePublicKey(aggnonce.sliceArray(33 until 66))
        
        // Q point is stored in keyaggCache (4..36 is X, 36..68 is Y)
        val Qx = PureBI.fromByteArray(keyaggCache.sliceArray(4 until 36))
        val Qy = PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68))
        val Q = Pair(Qx, Qy)
        
        // BIP-327: noncecoef uses XOnly PK (32 bytes), not compressed PK (33 bytes)
        // keyaggCache 4..36 is Q.x which is the XOnly representation (as we ensure Q is even in cache)
        val b = PureBI.fromByteArray(taggedHash("MuSig/noncecoef", aggnonce + keyaggCache.sliceArray(4 until 36) + msg32)) % N
        
        val bR2 = scalarMultiply(b, aggnonce_pt2.first, aggnonce_pt2.second)
        var R_pt = pointAdd(aggnonce_pt1.first, aggnonce_pt1.second, bR2.first, bR2.second)
        
        val R = if (isPointAtInfinity(R_pt.first, R_pt.second)) Pair(G_X, G_Y) else R_pt
        val Rx = encodePublicKey(R, true).sliceArray(1 until 33)
        
        val e = PureBI.fromByteArray(taggedHash("BIP0340/challenge", Rx + keyaggCache.sliceArray(4 until 36) + msg32)) % N
        
        val parity_acc = keyaggCache[164].toInt() and 1
        val parity_R = if (isOdd(R.second)) 1 else 0
        
        // BIP-327: gv (-1) if R is odd. Independent of Q parity.
        val gv = if (parity_R == 1) 1.toByte() else 0.toByte()
        
        val session = ByteArray(133)
        session[0] = gv
        b.toByteArray32().copyInto(session, 1)
        e.toByteArray32().copyInto(session, 33)
        keyaggCache.copyInto(session, 65, 164, 197)
        Rx.copyInto(session, 98)
        
        return session
    }


    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray {
        require(secnonce.size == 132)
        require(privkey.size == 32)
        require(session.size == 133)

        // Validate that secnonce belongs to this private key
        val pkPair = decodePublicKey(pubkeyCreate(privkey))
        val pkX_le = secnonce.sliceArray(68 until 100)
        val pkY_le = secnonce.sliceArray(100 until 132)
        
        // pkX and pkY in secnonce are little-endian
        val derivedPkX_le = pkPair.first.toByteArray32().reversedArray()
        val derivedPkY_le = pkPair.second.toByteArray32().reversedArray()
        
        if (!pkX_le.contentEquals(derivedPkX_le) || !pkY_le.contentEquals(derivedPkY_le)) {
            throw Secp256k1Exception("Invalid secnonce for this private key")
        }

        val k1 = PureBI.fromByteArray(secnonce.sliceArray(4 until 36))
        val k2 = PureBI.fromByteArray(secnonce.sliceArray(36 until 68))
        val sk = PureBI.fromByteArray(privkey)
        
        val b = PureBI.fromByteArray(session.sliceArray(1 until 33))
        val e = PureBI.fromByteArray(session.sliceArray(33 until 65))
        val parity_acc = session[65].toInt() and 1
        val g_acc = if (parity_acc == 1) N - PureBI.ONE else PureBI.ONE
        val gv = if (session[0].toInt() == 1) N - PureBI.ONE else PureBI.ONE
        
        val L = keyaggCache.sliceArray(132 until 164)
        val pk = encodePublicKey(decodePublicKey(pubkeyCreate(privkey)), true)
        
        // BIP-327: a_j = 1 if X_j == X_second
        val secondPkX = keyaggCache.sliceArray(68 until 100)
        val signingPkX = pk.sliceArray(1 until 33)
        
        
        val a = if (signingPkX.contentEquals(secondPkX)) {
            PureBI.ONE
        } else {
            PureBI.fromByteArray(taggedHash("KeyAgg coefficient", L + pk)) % N
        }
        
        // BIP-327: g_Q parity of Q (tweaked key)
        val Qy = PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68))
        val g_Q = if (isOdd(Qy)) N - PureBI.ONE else PureBI.ONE


        
        // s = (gv * (k1 + b * k2) + e * a * g_Q * g_acc * sk) % N
        // gv applies only to k (R parity). g_Q * g_acc applies to d.
        val s = (gv * (k1 + b * k2) + e * a * g_Q * g_acc * sk) % N

        return s.toByteArray32()
    }

    override fun musigPartialSigVerify(partialSig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int {
        val s = PureBI.fromByteArray(partialSig)
        if (s >= N) return 0
        
        val R1 = decodePublicKey(pubnonce.sliceArray(0 until 33))
        val R2 = decodePublicKey(pubnonce.sliceArray(33 until 66))
        val b = PureBI.fromByteArray(session.sliceArray(1 until 33))
        val e = PureBI.fromByteArray(session.sliceArray(33 until 65))
        
        val parity_acc = session[65].toInt() and 1
        val g_acc = if (parity_acc == 1) N - PureBI.ONE else PureBI.ONE
        val gv = if (session[0].toInt() == 1) N - PureBI.ONE else PureBI.ONE
        
         // BIP-327: g_Q parity of Q (tweaked key)
        val Qy = PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68))
        val g_Q = if (isOdd(Qy)) N - PureBI.ONE else PureBI.ONE

        val L = keyaggCache.sliceArray(132 until 164)
        val pki = encodePublicKey(decodePublicKey(pubkey), true)
        // BIP-327: a_j = 1 if X_j == X_second
        val secondPkX = keyaggCache.sliceArray(68 until 100)
        val signingPkX = pki.sliceArray(1 until 33)
        
        val a = if (signingPkX.contentEquals(secondPkX)) {
            PureBI.ONE
        } else {
            PureBI.fromByteArray(taggedHash("KeyAgg coefficient", L + pki)) % N
        }

        // Reconstruct R
        // R = R1 + b*R2
        val bR2 = scalarMultiply(b, R2.first, R2.second)
        val R_pt = pointAdd(R1.first, R1.second, bR2.first, bR2.second)
        val R = if (isPointAtInfinity(R_pt.first, R_pt.second)) Pair(G_X, G_Y) else R_pt
        val gvR = scalarMultiply(gv, R.first, R.second)
        

        
        val Pi = decodePublicKey(pki)
        // term2 = e * a * g_Q * g_acc * P
        val ea_g_acc = (e * a * g_Q * g_acc) % N
        val ea_g_acc_Pi = scalarMultiply(ea_g_acc, Pi.first, Pi.second)
        
        val target = pointAdd(gvR.first, gvR.second, ea_g_acc_Pi.first, ea_g_acc_Pi.second)
        val sG = scalarMultiply(s, G_X, G_Y)
        
        return if (sG.first == target.first && sG.second == target.second) 1 else 0
    }

    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray {
        var s_agg = PureBI.ZERO
        for (psig in psigs) {
            val s = PureBI.fromByteArray(psig)
            if (s >= N) throw IllegalArgumentException("Partial sig >= N")
            s_agg = (s_agg + s) % N
        }
        
        val e = PureBI.fromByteArray(session.sliceArray(33 until 65))
        // session[65] is parity_acc (from keyaggCache[164])
        // session[66..98] is t_acc (from keyaggCache[165..197])
        val t_acc = PureBI.fromByteArray(session.sliceArray(66 until 98))
        
        // BIP-327: s = sum(s_j) + e * g_Q * t_acc
        val g_Q = if (keyaggCache != null) {
            val Qy = PureBI.fromByteArray(keyaggCache.sliceArray(36 until 68))
            if (isOdd(Qy)) N - PureBI.ONE else PureBI.ONE
        } else PureBI.ONE

        s_agg = (s_agg + e * g_Q * t_acc) % N
        
        // Final signature = Rx || (s_agg + e * g_Q * t_acc) mod N
        val Rx = session.sliceArray(98 until 130)
        return Rx + s_agg.toByteArray32()
    }

    private fun pointAdd(x1: PureBI, y1: PureBI, x2: PureBI, y2: PureBI): Pair<PureBI, PureBI> {
        if (isPointAtInfinity(x1, y1)) return Pair(x2, y2)
        if (isPointAtInfinity(x2, y2)) return Pair(x1, y1)
        if (x1 == x2 && (y1 + y2) % P == PureBI.ZERO) return Pair(PureBI.ZERO, PureBI.ZERO)
        
        val s = if (x1 == x2 && y1 == y2) {
            val num = (PureBI(KmpBI.fromInt(3)) * x1 * x1) % P
            val den = (PureBI(KmpBI.fromInt(2)) * y1).modInverse(P)
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

    private fun scalarMultiply(k: PureBI, x: PureBI, y: PureBI): Pair<PureBI, PureBI> {
        var res = Pair(PureBI.ZERO, PureBI.ZERO)
        var temp = Pair(x, y)
        var scalar = k % N
        while (scalar > PureBI.ZERO) {
            if (scalar % PureBI(KmpBI.fromInt(2)) == PureBI.ONE) res = pointAdd(res.first, res.second, temp.first, temp.second)
            temp = pointAdd(temp.first, temp.second, temp.first, temp.second)
            scalar /= PureBI(KmpBI.fromInt(2))
        }
        return res
    }

    private fun generateKDeterministic(privkey: ByteArray, messageHash: ByteArray): PureBI {
        var v = ByteArray(32) { 1 }
        var k = ByteArray(32) { 0 }
        k = hmacSha256(k, v + byteArrayOf(0) + privkey + messageHash)
        v = hmacSha256(k, v)
        k = hmacSha256(k, v + byteArrayOf(1) + privkey + messageHash)
        v = hmacSha256(k, v)
        while (true) {
            v = hmacSha256(k, v)
            val candidate = PureBI.fromByteArray(v)
            if (candidate >= PureBI.ONE && candidate < N) return candidate
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

    private fun isDer(sig: ByteArray): Boolean {
        // Minimum DER signature length is usually: 0x30 + len + 0x02 + rLen + r + 0x02 + sLen + s
        // Minimal r, s is 1 byte -> 1+1+1+1+1+1+1+1 = 8 bytes?
        // Just checking 0x30 is a good heuristic for now combined with try-catch later.
        return sig.size > 8 && sig[0] == 0x30.toByte()
    }

    private fun encodeCompact(r: PureBI, s: PureBI): ByteArray = r.toByteArray32() + s.toByteArray32()

    private fun decodeCompact(signature: ByteArray): Pair<PureBI, PureBI> {
        require(signature.size == 64)
        val r = signature.sliceArray(0 until 32).toBigInteger()
        val s = signature.sliceArray(32 until 64).toBigInteger()
        require(r >= PureBI.ONE && r < N)
        require(s >= PureBI.ONE && s < N)
        return Pair(r, s)
    }

    private fun decodeDER(signature: ByteArray): Pair<PureBI, PureBI> {
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

    private fun encodeDER(r: PureBI, s: PureBI): ByteArray {
        val rb = r.toByteArrayDER()
        val sb = s.toByteArrayDER()
        return byteArrayOf(0x30, (rb.size + sb.size + 4).toByte(), 0x02, rb.size.toByte()) + rb + byteArrayOf(0x02, sb.size.toByte()) + sb
    }

    private fun decodePublicKey(pk: ByteArray): Pair<PureBI, PureBI> {
        if (pk.isEmpty()) throw Secp256k1Exception("Invalid public key")
        // MuSig2 uses 33 zero bytes to represent the point at infinity
        if (pk.size == 33 && pk.all { it == 0.toByte() }) return Pair(PureBI.ZERO, PureBI.ZERO)
        
        return when (pk[0]) {
            0x04.toByte(), 0x06.toByte(), 0x07.toByte() -> {
                if (pk.size != 65) throw Secp256k1Exception("Invalid public key")
                val x = PureBI.fromByteArray(pk.sliceArray(1 until 33))
                val y = PureBI.fromByteArray(pk.sliceArray(33 until 65))
                if (x >= P || x < PureBI.ZERO || y >= P || y < PureBI.ZERO) throw Secp256k1Exception("Invalid public key")
                if (!validatePointOnCurve(x, y)) throw Secp256k1Exception("Point not on curve")
                Pair(x, y)
            }
            0x02.toByte(), 0x03.toByte() -> {
                if (pk.size != 33) throw Secp256k1Exception("Invalid public key")
                val x = PureBI.fromByteArray(pk.sliceArray(1 until 33))
                if (x >= P || x < PureBI.ZERO) throw Secp256k1Exception("Invalid public key")
                val y = decompressY(x, pk[0] == 0x03.toByte())
                Pair(x, y)
            }
            else -> throw Secp256k1Exception("Invalid format: ${pk[0].toInt()}")
        }
    }

    private fun encodePublicKey(p: Pair<PureBI, PureBI>, compressed: Boolean): ByteArray {
        if (isPointAtInfinity(p.first, p.second)) {
            // MuSig2 encodes infinity as 33 or 65 zero bytes
            return if (compressed) ByteArray(33) else ByteArray(65)
        }
        return if (compressed) {
            val prefix = if (p.second % PureBI(KmpBI.fromInt(2)) == PureBI.ZERO) 0x02 else 0x03
            byteArrayOf(prefix.toByte()) + p.first.toByteArray32()
        } else {
            byteArrayOf(0x04) + p.first.toByteArray32() + p.second.toByteArray32()
        }
    }

    private fun decompressY(x: PureBI, isOdd: Boolean): PureBI {
        val alpha = (x * x * x + PureBI(KmpBI.fromInt(7))) % P
        val beta = alpha.modPow((P + PureBI.ONE) / PureBI(KmpBI.fromInt(4)), P)
        if ((beta * beta) % P != alpha) throw IllegalArgumentException("Not on curve")
        return if (isOdd(beta) == isOdd) beta else P - beta
    }

    private fun isPointAtInfinity(x: PureBI, y: PureBI): Boolean = x == PureBI.ZERO && y == PureBI.ZERO

    private fun isOdd(bi: PureBI): Boolean {
        val bytes = bi.magnitude.toByteArray()
        return bytes.isNotEmpty() && (bytes.last().toInt() and 1 != 0)
    }

    private fun hasEvenY(p: Pair<PureBI, PureBI>): Boolean = !isOdd(p.second)

    private fun liftX(x: PureBI): Pair<PureBI, PureBI> = Pair(x, decompressY(x, false))

    private fun validatePointOnCurve(x: PureBI, y: PureBI): Boolean = (y * y) % P == (x * x * x + PureBI(KmpBI.fromInt(7))) % P

    private fun taggedHash(tag: String, data: ByteArray): ByteArray {
        val head = SHA256().digest(tag.encodeToByteArray())
        return SHA256().digest(head + head + data)
    }

    private fun xor(a: ByteArray, b: ByteArray): ByteArray = ByteArray(a.size) { i -> (a[i].toInt() xor b[i].toInt()).toByte() }

    private class PureBI(internal val magnitude: KmpBI) {
        companion object {
            val ZERO: PureBI = PureBI(KmpBI.ZERO)
            val ONE: PureBI = PureBI(KmpBI.ONE)
            val TWO: PureBI = PureBI(KmpBI.fromInt(2))
            fun fromByteArray(b: ByteArray): PureBI = PureBI(KmpBI.fromByteArray(b, Sign.POSITIVE))
            fun fromHex(h: String): PureBI = PureBI(KmpBI.parseString(h, 16))
        }

        operator fun plus(o: PureBI): PureBI = PureBI(magnitude + o.magnitude)
        operator fun minus(o: PureBI): PureBI = PureBI(magnitude - o.magnitude)
        operator fun times(o: PureBI): PureBI = PureBI(magnitude * o.magnitude)
        operator fun div(o: PureBI): PureBI = PureBI(magnitude / o.magnitude)
        operator fun rem(o: PureBI): PureBI {
            val r = magnitude % o.magnitude
            return if (r < KmpBI.ZERO) PureBI(r + o.magnitude) else PureBI(r)
        }
        operator fun compareTo(o: PureBI): Int = magnitude.compareTo(o.magnitude)
        override fun equals(o: Any?): Boolean = o is PureBI && magnitude == o.magnitude
        override fun hashCode(): Int = magnitude.hashCode()
        override fun toString(): String = magnitude.toString(16)

        fun modInverse(m: PureBI): PureBI {
            var a = magnitude % m.magnitude
            if (a < KmpBI.ZERO) a += m.magnitude
            var m0 = m.magnitude
            var x0 = KmpBI.ZERO
            var x1 = KmpBI.ONE
            while (a > KmpBI.ONE) {
                val q = a / m0
                var t = m0
                m0 = a % m0
                a = t
                t = x0
                x0 = x1 - q * x0
                x1 = t
            }
            if (x1 < KmpBI.ZERO) x1 += m.magnitude
            return PureBI(x1)
        }

        fun modPow(e: PureBI, m: PureBI): PureBI {
            var res = KmpBI.ONE
            var b = magnitude % m.magnitude
            var exp = e.magnitude
            while (exp > KmpBI.ZERO) {
                if (exp % KmpBI.TWO == KmpBI.ONE) res = (res * b) % m.magnitude
                b = (b * b) % m.magnitude
                exp /= KmpBI.TWO
            }
            return PureBI(res)
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

    private fun ByteArray.toBigInteger(): PureBI = PureBI.fromByteArray(this)
    private fun ByteArray.toHex(): String = this.joinToString("") { it.toUByte().toString(16).padStart(2, '0') }
}
