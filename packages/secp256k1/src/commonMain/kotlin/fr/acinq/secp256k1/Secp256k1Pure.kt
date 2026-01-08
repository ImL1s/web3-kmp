package fr.acinq.secp256k1

import org.kotlincrypto.hash.sha2.SHA256
import com.ionspin.kotlin.bignum.integer.BigInteger as KmpBigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.experimental.xor

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
        val z = message.toBigInteger()
        val k = generateKDeterministic(privkey, message)
        val (kGx, _) = scalarMultiply(k, G_X, G_Y)
        val r = kGx % N
        require(r >= BigInteger.ONE && r < N)
        val kInv = k.modInverse(N)
        val s = (kInv * (z + r * d)) % N
        require(s >= BigInteger.ONE && s < N)
        return encodeCompact(r, s)
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
        val (r, s) = decodeCompact(sig)
        val nHalf = N / BigInteger(KmpBigInteger.fromInt(2))
        return if (s > nHalf) {
            val normalizedS = N - s
            Pair(encodeCompact(r, normalizedS), true)
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
        val (x, y) = scalarMultiply(d, G_X, G_Y)
        return byteArrayOf(0x04) + x.toByteArray32() + y.toByteArray32()
    }

    override fun pubkeyParse(pubkey: ByteArray): ByteArray {
        val (x, y) = decodePublicKey(pubkey)
        return byteArrayOf(0x04) + x.toByteArray32() + y.toByteArray32()
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
        val (sharedX, _) = scalarMultiply(d, pubX, pubY)
        return sharedX.toByteArray32()
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

    override fun musigNonceGen(sessionRandom32: ByteArray, privkey: ByteArray?, pubkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray = throw NotImplementedError()
    override fun musigNonceGenCounter(nonRepeatingCounter: ULong, privkey: ByteArray, msg32: ByteArray?, keyaggCache: ByteArray?, extraInput32: ByteArray?): ByteArray = throw NotImplementedError()
    override fun musigNonceAgg(pubnonces: Array<ByteArray>): ByteArray = throw NotImplementedError()
    override fun musigPubkeyAgg(pubkeys: Array<ByteArray>, keyaggCache: ByteArray?): ByteArray = throw NotImplementedError()
    override fun musigPubkeyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray = throw NotImplementedError()
    override fun musigPubkeyXonlyTweakAdd(keyaggCache: ByteArray, tweak32: ByteArray): ByteArray = throw NotImplementedError()
    override fun musigNonceProcess(aggnonce: ByteArray, msg32: ByteArray, keyaggCache: ByteArray): ByteArray = throw NotImplementedError()
    override fun musigPartialSign(secnonce: ByteArray, privkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): ByteArray = throw NotImplementedError()
    override fun musigPartialSigVerify(psig: ByteArray, pubnonce: ByteArray, pubkey: ByteArray, keyaggCache: ByteArray, session: ByteArray): Int = throw NotImplementedError()
    override fun musigPartialSigAgg(session: ByteArray, psigs: Array<ByteArray>): ByteArray = throw NotImplementedError()

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
        val rb = r.toByteArrayTrimmed()
        val sb = s.toByteArrayTrimmed()
        return byteArrayOf(0x30, (rb.size + sb.size + 4).toByte(), 0x02, rb.size.toByte()) + rb + byteArrayOf(0x02, sb.size.toByte()) + sb
    }

    private fun decodePublicKey(pk: ByteArray): Pair<BigInteger, BigInteger> {
        return when (pk[0]) {
            0x04.toByte() -> {
                require(pk.size == 65)
                Pair(pk.sliceArray(1 until 33).toBigInteger(), pk.sliceArray(33 until 65).toBigInteger())
            }
            0x02.toByte(), 0x03.toByte() -> {
                require(pk.size == 33)
                val x = pk.sliceArray(1 until 33).toBigInteger()
                val y = decompressY(x, pk[0] == 0x03.toByte())
                Pair(x, y)
            }
            else -> throw IllegalArgumentException("Invalid public key format")
        }
    }

    private fun encodePublicKey(p: Pair<BigInteger, BigInteger>, compressed: Boolean): ByteArray {
        return if (compressed) {
            val prefix = if (p.second % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO) 0x02 else 0x03
            byteArrayOf(prefix.toByte()) + p.first.toByteArray32()
        } else {
            byteArrayOf(0x04) + p.first.toByteArray32() + p.second.toByteArray32()
        }
    }

    private fun decompressY(x: BigInteger, isOdd: Boolean): BigInteger {
        val y2 = (x * x * x + BigInteger(KmpBigInteger.fromInt(7))) % P
        val y = y2.modPow((P + BigInteger.ONE) / BigInteger(KmpBigInteger.fromInt(4)), P)
        return if ((y % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ONE) == isOdd) y else P - y
    }

    private fun isPointAtInfinity(x: BigInteger, y: BigInteger): Boolean = x == BigInteger.ZERO && y == BigInteger.ZERO

    private fun hasEvenY(p: Pair<BigInteger, BigInteger>): Boolean = p.second % BigInteger(KmpBigInteger.fromInt(2)) == BigInteger.ZERO

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

        fun toByteArrayTrimmed(): ByteArray {
            val b = magnitude.toByteArray()
            return if (b.size > 1 && b[0] == 0.toByte()) b.sliceArray(1 until b.size) else b
        }
    }

    private fun ByteArray.toBigInteger(): BigInteger = BigInteger.fromByteArray(this)
}
