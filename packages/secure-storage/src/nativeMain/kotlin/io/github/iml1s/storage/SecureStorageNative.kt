package io.github.iml1s.storage

actual class PlatformContext

actual fun createSecureStorage(platformContext: PlatformContext): SecureStorage = object : SecureStorage {
    override suspend fun put(key: String, value: String) {
        throw UnsupportedSecureStorageException()
    }

    override suspend fun get(key: String): String? {
        throw UnsupportedSecureStorageException()
    }

    override suspend fun delete(key: String) {
        throw UnsupportedSecureStorageException()
    }

    override suspend fun clear() {
        throw UnsupportedSecureStorageException()
    }
}
