package io.github.iml1s.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger

/**
 * Merlin Transcript Protocol
 * 
 * Exact implementation of Strobe-128 as used in the rust 'merlin' crate.
 * Reference: https://github.com/dalek-cryptography/merlin/blob/master/src/strobe.rs
 */
class Merlin(label: String) {
    
    // Strobe-128 constants
    // N = 200 bytes
    // sec = 128 bits = 16 bytes
    // R = N - (2 * sec) / 8 - 2 = 200 - 32 - 2 = 166
    private val STROBE_R = 166
    
    private val state = ByteArray(200)
    private var pos = 0
    private var posBegin = 0
    private var curFlags: Byte = 0
    
    // Flags
    private val FLAG_I: Byte = 1
    private val FLAG_A: Byte = 2
    private val FLAG_C: Byte = 4
    private val FLAG_T: Byte = 8
    private val FLAG_M: Byte = 16
    private val FLAG_K: Byte = 32
    
    init {
        // Initialize state
        // st[0..6] = [1, STROBE_R + 2, 1, 0, 1, 96]
        state[0] = 1
        state[1] = (STROBE_R + 2).toByte()
        state[2] = 1
        state[3] = 0
        state[4] = 1
        state[5] = 96
        
        // st[6..18] = "STROBEv1.0.2"
        val strobeVer = "STROBEv1.0.2".encodeToByteArray()
        strobeVer.copyInto(state, 6)
        
        // keccak-f[1600]
        f1600(state)
        
        // meta_ad(protocol_label, false)
        // Merlin uses label="Merlin v1.0" or similar as protocol label?
        // Wait, Merlin::new(label) in Rust:
        // impl Transcript { pub fn new(label: &'static [u8]) -> Transcript { Strobe128::new(b"Merlin v1.0").(append_message(b"dom-sep", label)) } }
        // So Strobe is init with "Merlin v1.0", then app label is appended.
        metaAd("Merlin v1.0".encodeToByteArray(), false)
        appendMessage("dom-sep".encodeToByteArray(), label.encodeToByteArray())
    }
    
    // --- Public Merlin API ---
    
    fun appendMessage(label: ByteArray, message: ByteArray) {
        // meta_ad(label || little_endian(len(message)), false)
        // Note: Merlin rust does: 
        //  t.meta_ad(label, false);
        //  t.meta_ad(&u32_to_le_bytes(message.len() as u32), true);
        //  t.ad(message, false);
        
        metaAd(label, false)
        metaAd(littleEndian32(message.size), true)
        ad(message, false)
    }
    
    fun challengeBytes(label: ByteArray, length: Int): ByteArray {
        // t.meta_ad(label, false);
        // t.meta_ad(&u32_to_le_bytes(length as u32), true);
        // t.prf(&mut bytes, false);
        
        metaAd(label, false)
        metaAd(littleEndian32(length), true)
        
        val out = ByteArray(length)
        prf(out, false)
        return out
    }
    
    // --- Strobe Operations ---
    
    private fun metaAd(data: ByteArray, more: Boolean) {
        beginOp((FLAG_M.toInt() or FLAG_A.toInt()).toByte(), more)
        absorb(data)
    }
    
    private fun ad(data: ByteArray, more: Boolean) {
        beginOp(FLAG_A, more)
        absorb(data)
    }
    
    private fun prf(data: ByteArray, more: Boolean) {
        beginOp((FLAG_I.toInt() or FLAG_A.toInt() or FLAG_C.toInt()).toByte(), more)
        squeeze(data)
    }
    
    // --- Core Strobe Logic ---
    
    private fun beginOp(flags: Byte, more: Boolean) {
        if (more) {
            // Check flags consistency? (Skipping for now as we control calls)
            return
        }
        
        val oldBegin = posBegin
        posBegin = pos + 1
        curFlags = flags
        
        val head = byteArrayOf(oldBegin.toByte(), flags)
        absorb(head)
        
        // Force F if C or K is set and pos != 0
        val forceF = (flags.toInt() and (FLAG_C.toInt() or FLAG_K.toInt())) != 0
        if (forceF && pos != 0) {
            runF()
        }
    }
    
    private fun absorb(data: ByteArray) {
        for (byte in data) {
            state[pos] = (state[pos].toInt() xor byte.toInt()).toByte()
            pos++
            if (pos == STROBE_R) {
                runF()
            }
        }
    }
    
    private fun squeeze(data: ByteArray) {
        for (i in data.indices) {
            data[i] = state[pos]
            state[pos] = 0
            pos++
            if (pos == STROBE_R) {
                runF()
            }
        }
    }
    
    private fun runF() {
        // self.state[self.pos] ^= self.pos_begin;
        state[pos] = (state[pos].toInt() xor posBegin).toByte()
        
        // self.state[self.pos + 1] ^= 0x04;
        state[pos + 1] = (state[pos + 1].toInt() xor 0x04).toByte()
        
        // self.state[STROBE_R + 1] ^= 0x80;
        state[STROBE_R + 1] = (state[STROBE_R + 1].toInt() xor 0x80).toByte()
        
        f1600(state)
        
        pos = 0
        posBegin = 0
    }
    
    private fun f1600(state: ByteArray) {
        // Use Sha3.keccakF1600 wrapper
        // Convert ByteArray to LongArray
        val lanes = LongArray(25)
        for (i in 0 until 25) {
            var l: Long = 0
            for (j in 0 until 8) {
                l = l or ((state[i * 8 + j].toLong() and 0xFF) shl (j * 8))
            }
            lanes[i] = l
        }
        
        Sha3.keccakF1600(lanes)
        
        // Convert back
        for (i in 0 until 25) {
            val l = lanes[i]
            for (j in 0 until 8) {
                state[i * 8 + j] = ((l ushr (j * 8)) and 0xFF).toByte()
            }
        }
    }
    
    private fun littleEndian32(i: Int): ByteArray {
        return ByteArray(4) { idx -> (i shr (8 * idx)).toByte() }
    }
}
