package io.github.iml1s.storage

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlinx.coroutines.test.runTest

/**
 * Integration test for PlatformSecureStorage on Apple platforms (iOS/watchOS).
 * This tests the actual Keychain implementation.
 */
class PlatformSecureStorageTest {

    @Test
    fun testActualKeychainStorage() = runTest {
        val platformContext = PlatformContext()
        val storage = PlatformSecureStorage(platformContext)
        
        val testKey = "integration_test_key"
        val testValue = "secure_content_123"
        
        // 1. Ensure clean start
        storage.delete(testKey)
        assertNull(storage.get(testKey), "Key should be null before starting")
        
        // 2. Put and Get
        storage.put(testKey, testValue)
        val retrieved = storage.get(testKey)
        assertEquals(testValue, retrieved, "Retrieved value should match stored value")
        
        // 3. Update
        val newValue = "updated_content_456"
        storage.put(testKey, newValue)
        assertEquals(newValue, storage.get(testKey), "Updated value should match")
        
        // 4. Delete
        storage.delete(testKey)
        assertNull(storage.get(testKey), "Key should be null after deletion")
    }

    @Test
    fun testClearAll() = runTest {
        val storage = PlatformSecureStorage(PlatformContext())
        storage.put("clear_test_1", "val1")
        storage.put("clear_test_2", "val2")
        
        storage.clear()
        
        assertNull(storage.get("clear_test_1"), "Key 1 should be gone after clear")
        assertNull(storage.get("clear_test_2"), "Key 2 should be gone after clear")
    }
}
