package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.StringKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolicyTest {

    private fun parseKey(s: String): StringKey = StringKey(s)

    @Test
    fun testConcreteParse() {
        val policyStr = "pk(A)"
        val policy = Concrete.fromStr(policyStr, ::parseKey)
        assertTrue(policy is Concrete.Key)
        assertEquals("A", (policy as Concrete.Key).key.content)
    }

    @Test
    fun testConcreteAnd() {
        val policyStr = "and(pk(A),pk(B))"
        val policy = Concrete.fromStr(policyStr, ::parseKey)
        assertTrue(policy is Concrete.And)
        assertEquals(2, policy.subs.size)
        assertEquals("A", (policy.subs[0] as Concrete.Key).key.content)
        assertEquals("B", (policy.subs[1] as Concrete.Key).key.content)
    }

    @Test
    fun testConcreteOrWithProb() {
        val policyStr = "or(99@pk(A),1@pk(B))"
        val policy = Concrete.fromStr(policyStr, ::parseKey)
        assertTrue(policy is Concrete.Or)
        assertEquals(2, policy.subs.size)
        assertEquals(99u, policy.subs[0].first)
        assertEquals("A", (policy.subs[0].second as Concrete.Key).key.content)
        assertEquals(1u, policy.subs[1].first)
        assertEquals("B", (policy.subs[1].second as Concrete.Key).key.content)
    }

    @Test
    fun testLift() {
        val policyStr = "or(99@pk(A),1@pk(B))"
        val concrete = Concrete.fromStr(policyStr, ::parseKey)
        val semantic = concrete.lift()

        // Expect or(pk(A),pk(B)) which is Thresh(1, [pk(A), pk(B)])
        assertTrue(semantic is Semantic.Thresh)
        assertEquals(1, semantic.threshold.k)
        assertEquals(2, semantic.threshold.data.size)
        assertEquals("pk(A)", semantic.threshold.data[0].toString())
        assertEquals("pk(B)", semantic.threshold.data[1].toString())
    }

    @Test
    fun testNestedLift() {
        // and(pk(A), or(pk(B), pk(C)))
        // Lifted: And(pk(A), Or(pk(B), pk(C))) -> Thresh(2, [pk(A), Thresh(1, [pk(B), pk(C)])])
        // Normalized: Thresh(2, ...)
        
        val policyStr = "and(pk(A),or(pk(B),pk(C)))"
        val concrete = Concrete.fromStr(policyStr, ::parseKey)
        val semantic = concrete.lift()
        
        assertTrue(semantic is Semantic.Thresh)
        assertEquals(2, semantic.threshold.k)
        assertEquals(2, semantic.threshold.data.size)
        
        val child2 = semantic.threshold.data[1]
        assertTrue(child2 is Semantic.Thresh)
        assertEquals(1, child2.threshold.k)
        assertEquals(2, child2.threshold.data.size)
    }
}
