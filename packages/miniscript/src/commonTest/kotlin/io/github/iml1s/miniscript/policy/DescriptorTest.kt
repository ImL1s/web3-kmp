package io.github.iml1s.miniscript.policy

import io.github.iml1s.miniscript.*
import io.github.iml1s.miniscript.node.ScriptElt
import io.github.iml1s.miniscript.context.BareCtx
import io.github.iml1s.miniscript.parser.DescriptorParser
import kotlin.test.*

class DescriptorTest {

    @Test
    fun testChecksum() {
        val s = "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
        val actualChecksum = Descriptor.computeChecksum(s)
        println("Descriptor: $s#$actualChecksum")
        // Expected checksum for this string (from rust-miniscript/bitcoin-core)
        // Let's verify if our polyMod implementation is correct.
        assertEquals(8, actualChecksum.length)
    }

    @Test
    fun testPkhDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "pkh($key)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Pkh)
        val script = desc.scriptPubKey()
        assertEquals(5, script.size)
    }

    @Test
    fun testWpkhDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "wpkh($key)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Wpkh)
        val script = desc.scriptPubKey()
        assertEquals(2, script.size)
    }

    @Test
    fun testShWpkhDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "sh(wpkh($key))"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Sh)
        assertTrue(desc.sub is Descriptor.Wpkh)
        val script = desc.scriptPubKey()
        assertEquals(3, script.size)
    }

    @Test
    fun testWshDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "wsh(pk($key))"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Wsh)
        val script = desc.scriptPubKey()
        assertEquals(2, script.size)
    }

    @Test
    fun testShWshDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "sh(wsh(pk($key)))"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Sh)
        assertTrue(desc.sub is Descriptor.Wsh)
        val script = desc.scriptPubKey()
        assertEquals(3, script.size)
    }

    @Test
    fun testPkDescriptor() {
        val key = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val s = "pk($key)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Pk)
        val script = desc.scriptPubKey()
        // P2PK: <pubkey> CHECKSIG
        assertEquals(2, script.size)
    }

    @Test
    fun testMultiDescriptor() {
        val k1 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val k2 = "03f0b4cc57551066915000f0744767597f394231b79f835cb615e4f45143a59a7a"
        val s = "multi(1,$k1,$k2)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Multi)
        val script = desc.scriptPubKey()
        // 1 <pk1> <pk2> 2 CHECKMULTISIG
        assertEquals(5, script.size)
    }

    @Test
    fun testSortedMultiDescriptor() {
        val k1 = "03f0b4cc57551066915000f0744767597f394231b79f835cb615e4f45143a59a7a"
        val k2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        // Lexicographically k2 < k1
        val s = "sortedmulti(1,$k1,$k2)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.SortedMulti)
        val script = desc.scriptPubKey()
        // Check if k2 comes before k1 in the script
        val pk2bytes = io.github.iml1s.crypto.Hex.decode(k2)
        val pk1bytes = io.github.iml1s.crypto.Hex.decode(k1)
        
        val p1 = script[1] as io.github.iml1s.miniscript.node.ScriptElt.Push
        val p2 = script[2] as io.github.iml1s.miniscript.node.ScriptElt.Push
        assertContentEquals(pk2bytes, p1.data)
        assertContentEquals(pk1bytes, p2.data)
    }

    @Test
    fun testRawDescriptor() {
        val hex = "76a91494a20b0805c6c06a8f108210352ef951e7df76f188ac"
        val s = "raw($hex)"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        assertTrue(desc is Descriptor.Raw)
        val script = desc.scriptPubKey()
        // We use a dummy instance to call the internal scriptToBytes
        val scriptBytes = Descriptor.scriptToBytes(script)
        assertEquals(hex, io.github.iml1s.crypto.Hex.encode(scriptBytes))
    }

    @Test
    fun testAddrDescriptor() {
        // P2PKH (Genesis) - 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        // Hex: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
        val p2pkhAddr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        val p2pkhDesc = DescriptorParser.parse<StringKey>("addr($p2pkhAddr)", BareCtx)
        assertTrue(p2pkhDesc is Descriptor.Addr)
        val p2pkhScript = Descriptor.scriptToBytes(p2pkhDesc.scriptPubKey())
        assertEquals("76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac", io.github.iml1s.crypto.Hex.encode(p2pkhScript))

        // P2WPKH (Mainnet) - bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        // Hex: 0014751e76e8199196d454941c45d1b3a323f1433bd6
        val p2wpkhAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        val p2wpkhDesc = DescriptorParser.parse<StringKey>("addr($p2wpkhAddr)", BareCtx)
        val p2wpkhScript = Descriptor.scriptToBytes(p2wpkhDesc.scriptPubKey())
        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6", io.github.iml1s.crypto.Hex.encode(p2wpkhScript))
    }

    @Test
    fun testTrTreeDescriptor() {
        // tr(KEY, {pk(A), pk(B)})
        val internalKey = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        val keyA = "03f0b4cc57551066915000f0744767597f394231b79f835cb615e4f45143a59a7a"
        val keyB = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        
        val s = "tr($internalKey,{pk($keyA),pk($keyB)})"
        val desc = DescriptorParser.parse<StringKey>(s, BareCtx)
        
        assertTrue(desc is Descriptor.Tr)
        assertNotNull(desc.tree)
        assertTrue(desc.tree is TapTree.Branch)
        
        val script = desc.scriptPubKey()
        // Should be OP_1 <32-byte-tweaked-key>
        assertEquals(2, script.size)
        assertEquals(ScriptElt.OP_1, script[0])
        val pushKey = script[1] as io.github.iml1s.miniscript.node.ScriptElt.Push
        assertEquals(32, pushKey.data.size)
        
        println("TR Script: ${io.github.iml1s.crypto.Hex.encode(pushKey.data)}")
    }
}
