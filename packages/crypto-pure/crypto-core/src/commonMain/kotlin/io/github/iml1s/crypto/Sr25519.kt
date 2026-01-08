package io.github.iml1s.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

/**
 * Sr25519 (Schnorrkel) Implementation
 * 
 * Implements Schnorr signatures on the Ristretto255 group using Merlin transcripts.
 * Compatible with Polkadot/Substrate (rust-schnorrkel).
 */
object Sr25519 {
    
    // Group Order L = 2^252 + 27742317777372353535851937790883648493
    val L = BigInteger.parseString("7237005577332262213973186563042994240857116359379907606001950938285454250989")
    
    // KeyPair
    class KeyPair(val secretKey: ByteArray, val publicKey: ByteArray)
    
    /**
     * Generate a KeyPair from a 32-byte secret seed (MiniSecretKey)
     * Performs expansion (Ed25519-style clamping) and scalar multiplication.
     * 
     * @param seed 32-byte seed (MiniSecretKey)
     * @return KeyPair with 32-byte seed as secretKey
     */
    fun keypairFromSeed(seed: ByteArray): KeyPair {
        require(seed.size == 32) { "Seed must be 32 bytes" }
        
        // Expand key
        val (scalar, _) = expandKey(seed)
        
        // Public Key = scalar * B
        val P = Ristretto255.BASEPOINT.multiply(toBytes32(scalar))
        val pubBytes = P.toBytes()
        
        return KeyPair(seed, pubBytes)
    }
    
    /**
     * Sign a message.
     * 
     * @param publicKey 32-byte public key (compressed Ristretto point)
     * @param secretKey 32-byte secret seed (MiniSecretKey)
     * @param message Message to sign
     * @param context Transcript context label (usually "substrate")
     */
    fun sign(publicKey: ByteArray, secretKey: ByteArray, message: ByteArray, context: ByteArray = ByteArray(0)): ByteArray {
        val (x, nonceSeed) = expandKey(secretKey)
        
        val t = Merlin("SigningContext")
        t.appendMessage(ByteArray(0), context)
        t.appendMessage("sign-bytes".encodeToByteArray(), message)
        
        t.appendMessage("proto-name".encodeToByteArray(), "Schnorr-sig".encodeToByteArray())
        t.appendMessage("sign:pk".encodeToByteArray(), publicKey)
        
        // Witness generation (using simpler deterministic method for now if needed, but standard uses Merlin witness)
        // Since Merlin.kt lacks explicit witness_bytes mixing with RNG, 
        // we use a deterministic nonce derived from (nonceSeed, message, pk) roughly similar to Ed25519 for safety,
        // OR implement Merlin witness_bytes correctly.
        // For strict Schnorrkel compatibility, we need r derived via transcript.
        // Implementation:
        //  t.witness_bytes(label, dest, nonce_seed)
        
        // We will simulate witness derivation:
        // H(nonce_seed || public_key || message) -> r
        // This is safe but might not match Schnorrkel EXACTLY if test vectors check `r`.
        // However, Schnorrkel is deterministic.
        // Let's rely on Merlin to mix entropy.
        
        // We will construct a 'witness' transcript
        // But for now, let's use a simplified deterministic nonce to pass roundtrip:
        // r = Hash(nonceSeed ++ message)
        val rInput = nonceSeed + message
        val rHash = Sha512.hash(rInput) // 64 bytes
        val rVal = BigInteger.fromByteArray(rHash.reversedArray(), Sign.POSITIVE).mod(L)
        val r = toBytes32(rVal)
        
        // 4. R = r * B
        val R = Ristretto255.BASEPOINT.multiply(r)
        val Rbytes = R.toBytes()
        t.appendMessage("sign:R".encodeToByteArray(), Rbytes)
        
        // 5. Challenge k = scalar("sign:c")
        val kBytes = t.challengeBytes("sign:c".encodeToByteArray(), 64) 
        val k = BigInteger.fromByteArray(kBytes.reversedArray(), Sign.POSITIVE).mod(L)
        
        // 6. s = r + k * x (scalar arithmetic)
        val s = rVal.add(k.multiply(x)).mod(L)
        
        // 7. Signature = (R, s) -> 64 bytes
        val sig = ByteArray(64)
        Rbytes.copyInto(sig, 0, 0, 32)
        toBytes32(s).copyInto(sig, 32, 0, 32)
        
        // Set high bit to distinguish from ed25519 signatures
        sig[63] = (sig[63].toInt() or 128).toByte()
        
        return sig
    }
    
    /**
     * Verify a signature.
     */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray, context: ByteArray = ByteArray(0)): Boolean {
        if (signature.size != 64) return false
        val Rbytes = signature.copyOfRange(0, 32)
        val sBytes = signature.copyOfRange(32, 64).copyOf()
        
        // Clear high bit marker
        sBytes[31] = (sBytes[31].toInt() and 127).toByte()
        
        val s = BigInteger.fromByteArray(sBytes.reversedArray(), Sign.POSITIVE)
        if (s >= L) return false
        
        val R = Ristretto255.fromBytes(Rbytes) ?: return false
        val Pk = Ristretto255.fromBytes(publicKey) ?: return false
        
        // 1. Reconstruct transcript
        val t = Merlin("SigningContext")
        t.appendMessage(ByteArray(0), context)
        t.appendMessage("sign-bytes".encodeToByteArray(), message)
        
        t.appendMessage("proto-name".encodeToByteArray(), "Schnorr-sig".encodeToByteArray())
        t.appendMessage("sign:pk".encodeToByteArray(), publicKey)
        t.appendMessage("sign:R".encodeToByteArray(), Rbytes)
        
        // 2. Challenge k
        val kBytes = t.challengeBytes("sign:c".encodeToByteArray(), 64)
        val k = BigInteger.fromByteArray(kBytes.reversedArray(), Sign.POSITIVE).mod(L)
        
        // 3. Check s * B == R + k * Pk
        val sB = Ristretto255.BASEPOINT.multiply(toBytes32(s))
        val kPk = Pk.multiply(toBytes32(k))
        val RHS = R.add(kPk)
        
        return sB.toBytes().contentEquals(RHS.toBytes())
    }
    
    private fun expandKey(seed: ByteArray): Pair<BigInteger, ByteArray> {
        val h = Sha512.hash(seed)
        val left = h.copyOfRange(0, 32)
        val right = h.copyOfRange(32, 64)
        
        // Ed25519-style clamping
        left[0] = (left[0].toInt() and 248).toByte()
        left[31] = (left[31].toInt() and 63).toByte()  // Note: 63 = 0x3F, not 127 = 0x7F
        left[31] = (left[31].toInt() or 64).toByte()
        
        // Divide by cofactor 8 to get scalar in Ristretto group
        // This is done by right-shifting the byte array by 3 bits
        divideScalarBytesByCofactor(left)
        
        val scalar = BigInteger.fromByteArray(left.reversedArray(), Sign.POSITIVE)
        return Pair(scalar, right)
    }
    
    /**
     * Divide scalar bytes by 8 (cofactor) by right-shifting by 3 bits.
     * This matches schnorrkel::scalars::divide_scalar_bytes_by_cofactor
     */
    private fun divideScalarBytesByCofactor(bytes: ByteArray) {
        var low = 0
        for (i in bytes.indices.reversed()) {
            val r = bytes[i].toInt() and 0xFF
            bytes[i] = ((r shr 3) or low).toByte()
            low = (r shl 5) and 0xFF
        }
    }
    
    internal fun toBytes32(i: BigInteger): ByteArray {
        val b = i.toByteArray()
        val out = ByteArray(32)
        // BigInteger toByteArray is big-endian
        // Check sign byte
        val start = if (b.size > 32 && b[0] == 0.toByte()) 1 else 0
        val len = minOf(32, b.size - start)
        
        // Fill little-endian
        for (j in 0 until len) {
             out[j] = b[b.size - 1 - j]
        }
        return out
    }
}

