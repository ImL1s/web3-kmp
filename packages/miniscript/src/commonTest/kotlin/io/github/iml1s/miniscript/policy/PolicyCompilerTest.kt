package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.Miniscript
import io.github.iml1s.miniscript.StringKey
import io.github.iml1s.miniscript.context.BareCtx
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolicyCompilerTest {

    @Test
    fun testBasicCompilation() {
        val policyStr = "and(pk(A),pk(B))"
        // Naive compilation: and_b(pk(A),pk(B))
        // Note: Miniscript.fromStr parses 'pk' as Terminal.Pk
        // Concrete.fromStr parses 'pk' as Concrete.Key
        
        val policy = Concrete.fromStr<StringKey>(policyStr) { StringKey(it) }
        val miniscript = policy.compile()
        
        println("Compiled: ${miniscript.scriptPubKey()}")
        
        // Check if output is valid Miniscript (structure)
        // With naive and_b, we expect: and_b(pk(A),pk(B))
        // However, Terminal.toString() might differ.
        
        // Let's verify the type system accepts it.
        // and_b requires B, B -> B.
        // pk(A) is B.
        // So this should be valid.
    }

    @Test
    fun testOrCompilation() {
        val policyStr = "or(pk(A),older(10))"
        // Naive: or_b(pk(A),older(10))
        val policy = Concrete.fromStr<StringKey>(policyStr) { StringKey(it) }
        val miniscript = policy.compile()
        
        println("Compiled OR: ${miniscript.scriptPubKey()}")
    }
    
    @Test
    fun testThresh() {
         val policyStr = "thresh(2,pk(A),pk(B),pk(C))"
         val policy = Concrete.fromStr<StringKey>(policyStr) { StringKey(it) }
         val miniscript = policy.compile()
         println("Compiled: ${miniscript.scriptPubKey()}")
    }
}
