package io.github.iml1s.storage

import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class JvmVaultP1Test {

    @Test
    fun decryptFailureIsNotEmptyAndPutDoesNotOverwrite() = runTest {
        val tmp = kotlin.io.path.createTempDirectory("kotlin-crypto-vault").toFile()
        val previousHome = System.getProperty("user.home")
        System.setProperty("user.home", tmp.absolutePath)
        try {
            val storage = createSecureStorage(Any())
            storage.put("secret", "alpha")
            val vault = File(tmp, ".kotlin-crypto/secure_storage.dat")
            assertTrue(vault.exists())
            val original = vault.readBytes()
            val tampered = original.copyOf()
            tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0x01).toByte()
            vault.writeBytes(tampered)

            val again = createSecureStorage(Any())
            val getEx = assertFails { again.get("secret") }
            assertTrue(getEx is VaultCorruptException)

            val putEx = assertFails { again.put("other", "beta") }
            assertTrue(putEx is VaultCorruptException)
            assertTrue(vault.readBytes().contentEquals(tampered), "corrupt vault bytes must be unchanged")
        } finally {
            System.setProperty("user.home", previousHome)
        }
    }

    @Test
    fun missingVaultGetIsNullThenPutCreates() = runTest {
        val tmp = kotlin.io.path.createTempDirectory("kotlin-crypto-vault-empty").toFile()
        val previousHome = System.getProperty("user.home")
        System.setProperty("user.home", tmp.absolutePath)
        try {
            val storage = createSecureStorage(Any())
            assertEquals(null, storage.get("missing"))
            storage.put("k", "v")
            assertEquals("v", storage.get("k"))
        } finally {
            System.setProperty("user.home", previousHome)
        }
    }
}
