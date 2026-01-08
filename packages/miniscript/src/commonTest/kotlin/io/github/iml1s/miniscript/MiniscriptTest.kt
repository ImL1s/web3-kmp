package io.github.iml1s.miniscript

import io.github.iml1s.miniscript.context.BareCtx
import kotlin.test.*

class MiniscriptTest {

    @Test
    fun testCompilePk() {
        val s = "pk(02e93b131970273f00965824c8806612df9d949479369994c632830f657519e9cd)"
        val ms = Miniscript.fromStr<StringKey, BareCtx>(s, BareCtx)
        val script = ms.scriptPubKey()
        // pk(X) is c:pk_k(X) -> <pkX> CHECKSIG (ac)
        assertEquals("2102e93b131970273f00965824c8806612df9d949479369994c632830f657519e9cdac", script)
    }

    @Test
    fun testCompileAndV() {
        // and_v(pk(A),pk(B)) -> <pkA> <pkB> CHECKSIGVERIFY CHECKSIG (wait, no)
        // pk(A) -> c:pk_k(A) -> <pkA> CHECKSIG
        // and_v(pk(A),pk(B)) -> <pkA> CHECKSIG <pkB> CHECKSIG
        val s = "and_v(v:pk(02e93b131970273f00965824c8806612df9d949479369994c632830f657519e9cd),pk(020202020202020202020202020202020202020202020202020202020202020202))"
        val ms = Miniscript.fromStr<StringKey, BareCtx>(s, BareCtx)
        val script = ms.scriptPubKey()
        // v:pk(A) -> <pkA> CHECKSIGVERIFY
        // pk(B) -> <pkB> CHECKSIG
        assertTrue(script.contains("ad")) // OP_CHECKSIGVERIFY
        assertTrue(script.contains("ac")) // OP_CHECKSIG
    }

    @Test
    fun testCompileThresh() {
        val s = "thresh(2,pk(02e93b131970273f00965824c8806612df9d949479369994c632830f657519e9cd),s:pk(020202020202020202020202020202020202020202020202020202020202020202))"
        val ms = Miniscript.fromStr<StringKey, BareCtx>(s, BareCtx)
        val script = ms.scriptPubKey()
        // [pkA] CHECKSIG [pkB] CHECKSIG SWAP ADD 02 EQUAL
        // s:X -> OP_SWAP X
        assertTrue(script.contains("7c")) // OP_SWAP
        assertTrue(script.endsWith("93010287")) // ADD 2 EQUAL
    }
}
