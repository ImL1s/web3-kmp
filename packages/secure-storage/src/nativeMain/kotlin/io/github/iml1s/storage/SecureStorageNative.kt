package io.github.iml1s.storage

actual class PlatformContext

actual fun createSecureStorage(platformContext: PlatformContext): SecureStorage = object : SecureStorage {
    override suspend fun put(key: String, value: String) {
        // Native placeholder implementation
    }

    override suspend fun get(key: String): String? {
        return null
    }

    override suspend fun delete(key: String) {
    }

    override suspend fun clear() {
    }
}
