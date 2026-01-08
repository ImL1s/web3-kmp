package io.github.iml1s.crypto

/**
 * Near Protocol Address Generation
 * 
 * Near supports two types of accounts:
 * 1. Named accounts: Human-readable (e.g., "alice.near")
 * 2. Implicit accounts: 64-char hex string from Ed25519 public key
 * 
 * This implementation handles implicit accounts.
 * Path: m/44'/397'/0' (SLIP-10 Ed25519)
 */
object Near {
    
    const val COIN_TYPE = 397
    
    /**
     * Generate Near implicit account ID from Ed25519 public key.
     * 
     * The implicit account ID is simply the lowercase hex encoding
     * of the 32-byte Ed25519 public key.
     * 
     * @param publicKey Ed25519 public key (32 bytes)
     * @return 64-character lowercase hex string
     */
    fun getImplicitAccountId(publicKey: ByteArray): String {
        require(publicKey.size == 32) { "Public key must be 32 bytes (Ed25519)" }
        return Hex.encode(publicKey)
    }
    
    /**
     * Validate a Near account ID.
     * 
     * Rules:
     * - Implicit: 64 lowercase hex characters
     * - Named: 2-64 chars, alphanumeric + _ and -, must not start/end with - or _
     */
    fun isValidAccountId(accountId: String): Boolean {
        // Check implicit account (64 hex chars)
        if (accountId.length == 64 && accountId.all { it in '0'..'9' || it in 'a'..'f' }) {
            return true
        }
        
        // Check named account
        if (accountId.length < 2 || accountId.length > 64) return false
        if (accountId.startsWith("-") || accountId.startsWith("_")) return false
        if (accountId.endsWith("-") || accountId.endsWith("_")) return false
        
        return accountId.all { it in 'a'..'z' || it in '0'..'9' || it == '_' || it == '-' || it == '.' }
    }
    
    /**
     * Get derivation path for Near (SLIP-10 Ed25519)
     */
    fun getDerivationPath(account: Int = 0): String {
        return "m/44'/$COIN_TYPE'/$account'"
    }
}
