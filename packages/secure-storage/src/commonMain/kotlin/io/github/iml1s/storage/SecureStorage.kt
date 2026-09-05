package io.github.iml1s.storage

// Common
expect class PlatformContext

interface SecureStorage {
    suspend fun put(key: String, value: String)
    suspend fun get(key: String): String?
    suspend fun delete(key: String)
    suspend fun clear()
}

open class SecureStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)

class VaultCorruptException(message: String, cause: Throwable? = null) :
    SecureStorageException(message, cause)

class VaultIOException(message: String, cause: Throwable? = null) :
    SecureStorageException(message, cause)

class UnsupportedSecureStorageException(message: String = "SecureStorage is not implemented on this target") :
    SecureStorageException(message)

// Expect a factory function instead of expect class extending interface
expect fun createSecureStorage(platformContext: PlatformContext): SecureStorage
