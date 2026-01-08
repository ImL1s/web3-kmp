package io.github.iml1s.miniscript

import io.github.iml1s.crypto.Hex
import io.github.iml1s.miniscript.context.BareCtx
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class MiniscriptOfficialTest {
    // Standard Compressed Keys (33 bytes)
    val KEY_A = "020000000000000000000000000000000000000000000000000000000000000001"
    val KEY_B = "020000000000000000000000000000000000000000000000000000000000000002"
    val KEY_C = "020000000000000000000000000000000000000000000000000000000000000003"
    
    // Pre-computed Hash160 for KEYS (Generic placeholder logic until computed)
    // We will verify the script *structure* and that the hash matches the key's hash160 dynamically.
    
    @Test
    fun testValidVectors() {
        val testCases = listOf(
            // 1. Basic Pk (Key)
            // pk(A) -> <A> CHECKSIG
            TestCase("pk($KEY_A)", "21${KEY_A}ac"),
            
            // 2. Pkh (Key Hash)
            // pkh(A) -> DUP HASH160 <HASH160(A)> EQUALVERIFY CHECKSIG
            // 76 (DUP) a9 (HASH160) 14 (PUSH 20) <HASH> 88 (EQUALVERIFY) ac (CHECKSIG)
            // We compute expected hash dynamically to ensure test self-consistency with crypto lib
            TestCase("pkh($KEY_A)") {
                val hash = StringKey(KEY_A).toHash160(byteArrayOf())
                "76a914${Hex.encode(hash)}88ac"
            },

            // 3. True / False
            TestCase("1", "51"),
            TestCase("0", "00"),

            // 4. Older / After (Timelocks)
            // older(1) -> <1> CHECKSEQUENCEVERIFY -> 0101b2
            TestCase("older(1)", "0101b2"), 
            // after(1) -> <1> CHECKLOCKTIMEVERIFY -> 0101b1
            TestCase("after(1)", "0101b1"),

            // 5. Sha256 (Hash)
            // sha256(H) -> SIZE <32> EQUALVERIFY SHA256 <H> EQUAL
            // 82 (SIZE) 0120 (PUSH 32) 88 (EQUALVERIFY) a8 (SHA256) 20 (PUSH 32) <H> 87 (EQUAL)
            TestCase("sha256(0000000000000000000000000000000000000000000000000000000000000000)", 
                "82012088a820000000000000000000000000000000000000000000000000000000000000000087"),

            // 6. and_v (Verify combination)
            // and_v(v:pk(A),pk(B)) -> <pkA> CHECKSIGVERIFY <pkB> CHECKSIG
            // v:pk(A) -> c:pk_k(A) + v: -> <A> CHECKSIG + VERIFY -> <A> CHECKSIGVERIFY (ad)
            TestCase("and_v(v:pk($KEY_A),pk($KEY_B))", "21${KEY_A}ad21${KEY_B}ac"),

            // 7. and_b (Boolean combination)
            // and_b(pk(A),s:pk(B)) -> <pkA> CHECKSIG <pkB> CHECKSIG ADD <2> EQUAL ? 
            // Correct and_b logic: X Y BOOLAND -> 9a (BOOLAND). 
            // Structure: [X] [Y] BOOLAND
            TestCase("and_b(pk($KEY_A),s:pk($KEY_B))", "21${KEY_A}ac7c21${KEY_B}ac9a"),

            // 8. or_b (Or Boolean)
            // or_b(pk(A),s:pk(B)) -> [X] [Y] BOOLOR (9b)
            TestCase("or_b(pk($KEY_A),s:pk($KEY_B))", "21${KEY_A}ac7c21${KEY_B}ac9b"),

            // 9. thresh (Threshold)
            // thresh(2,pk(A),s:pk(B)) -> [pkA] CHECKSIG [pkB] CHECKSIG ADD ... check Miniscript logic
            // Miniscript: thresh(k, X1, X2, ...) => X1 + X2 + ... EQUAL k
            // For 2 args: [X1] [s:X2] ADD ...
            // s:X2 -> SWAP X2
            // [pkA] CHECKSIG SWAP [pkB] CHECKSIG ADD 2 EQUAL
            TestCase("thresh(2,pk($KEY_A),s:pk($KEY_B))", "21${KEY_A}ac7c21${KEY_B}ac93010287"),

            // 10. multi (Multisig)
            // multi(1,A,B) -> 1 <A> <B> 2 CHECKMULTISIG
            // 51 (1) 21<A> 21<B> 52 (2) ae (CHECKMULTISIG)
            // Note: Miniscript 'multi' might sort keys? Our implementation currently takes order as is.
            TestCase("multi(1,$KEY_A,$KEY_B)", "5121${KEY_A}21${KEY_B}52ae")
        )

        for ((i, case) in testCases.withIndex()) {
            try {
                // Explicitly provide type arguments <StringKey, BareCtx>
                val ms = Miniscript.fromStr<StringKey, BareCtx>(case.mini, BareCtx)
                val script = ms.scriptPubKey()
                val expected = case.scriptCalc()
                assertEquals(expected, script, "Test Case #$i Failed: ${case.mini}")
                println("Test Case #$i Passed: ${case.mini}")
            } catch (e: Exception) {
                fail("Test Case #$i Exception: ${case.mini} - ${e.message}")
            }
        }
    }

    @Test
    fun testInvalidVectors() {
        val invalidCases = listOf(
            // Typo / Syntax
            "pk", 
            "pk()",
            "unknown(A)",
            
            // Type Errors
            // and_v expects V as first child. pk(A) is B (expression, non-verify).
            "and_v(pk($KEY_A),pk($KEY_B))",
            
            // or_b expects B for both.
            // v:pk(A) is V.
            "or_b(v:pk($KEY_A),pk($KEY_B))",
            
            // thresh with k > n
            "thresh(3,pk($KEY_A),s:pk($KEY_B))",
            
            // duplicate keys in multi (usually invalid in strict mode, parser might just accept but let's check basic syntax)
            
            // wrappers on wrong types?
            // v: wrapper expects B, K, or W. 
            // v:v:pk(A) -> v: on V? Invalid.
            "v:v:pk($KEY_A)"
        )

        for ((i, case) in invalidCases.withIndex()) {
            try {
                Miniscript.fromStr<StringKey, BareCtx>(case, BareCtx)
                // If we reach here, it failed to throw
                fail("Test Case #$i Should Invalid: $case")
            } catch (e: Exception) {
                // Expected failure
                println("Test Case #$i Valid Invalid: $case - ${e.message}")
            }
        }
    }

    class TestCase(val mini: String, val calc: () -> String) {
        constructor(mini: String, scriptVal: String) : this(mini, { scriptVal })
        fun scriptCalc() = calc()
    }
}
