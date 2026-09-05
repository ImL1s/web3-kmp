package io.github.iml1s.storage

import java.io.File
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom
import java.util.EnumSet
import java.util.Properties
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

actual typealias PlatformContext = Any

class JvmSecureStorage(platformContext: PlatformContext) : SecureStorage {
    private val storageDir = File(System.getProperty("user.home"), ".kotlin-crypto").apply {
        if (!exists()) {
            mkdirs()
            runCatching {
                Files.setPosixFilePermissions(
                    toPath(),
                    EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
                )
            }
        }
    }
    private val storageFile = File(storageDir, "secure_storage.dat")
    private val keyFile = File(storageDir, ".key")

    private val IV_SIZE = 12
    private val TAG_SIZE = 128
    private val AES_KEY_SIZE = 256

    private val secretKey: SecretKey by lazy { getOrGenerateKey() }
    private val lock = Any()

    override suspend fun put(key: String, value: String) {
        synchronized(lock) {
            val properties = loadProperties(allowMissing = true)
            properties.setProperty(key, value)
            saveProperties(properties)
        }
    }

    override suspend fun get(key: String): String? {
        synchronized(lock) {
            val properties = loadProperties(allowMissing = true)
            return properties.getProperty(key)
        }
    }

    override suspend fun delete(key: String) {
        synchronized(lock) {
            val properties = loadProperties(allowMissing = true)
            properties.remove(key)
            saveProperties(properties)
        }
    }

    override suspend fun clear() {
        synchronized(lock) {
            if (storageFile.exists() && !storageFile.delete()) {
                throw VaultIOException("Failed to delete vault")
            }
        }
    }

    private fun getOrGenerateKey(): SecretKey {
        if (keyFile.exists()) {
            if (storageFile.exists() && keyFile.length() == 0L) {
                throw VaultCorruptException("Vault exists but key file is empty")
            }
            return SecretKeySpec(keyFile.readBytes(), "AES")
        }
        if (storageFile.exists()) {
            throw VaultCorruptException("Vault exists but key file is missing")
        }
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(AES_KEY_SIZE)
        val key = keyGen.generateKey()
        val tmp = File(storageDir, ".key.tmp")
        tmp.writeBytes(key.encoded)
        runCatching {
            Files.setPosixFilePermissions(
                tmp.toPath(),
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            )
        }
        Files.move(tmp.toPath(), keyFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        runCatching {
            Files.setPosixFilePermissions(
                keyFile.toPath(),
                EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            )
        }
        return key
    }

    private fun loadProperties(allowMissing: Boolean): Properties {
        val props = Properties()
        if (!storageFile.exists()) {
            if (allowMissing) return props
            throw VaultCorruptException("Vault is missing")
        }
        if (storageFile.length() == 0L) {
            throw VaultCorruptException("Vault file is empty")
        }
        try {
            val encryptedData = storageFile.readBytes()
            val byteBuffer = ByteBuffer.wrap(encryptedData)
            if (byteBuffer.remaining() < IV_SIZE + 16) {
                throw VaultCorruptException("Vault file is truncated")
            }
            val iv = ByteArray(IV_SIZE)
            byteBuffer.get(iv)
            val cipherText = ByteArray(byteBuffer.remaining())
            byteBuffer.get(cipherText)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE, iv))
            val decryptedData = cipher.doFinal(cipherText)
            props.load(decryptedData.inputStream())
            return props
        } catch (e: VaultCorruptException) {
            throw e
        } catch (e: Exception) {
            throw VaultCorruptException("Vault authentication or format failure", e)
        }
    }

    private fun saveProperties(props: Properties) {
        val outputStream = java.io.ByteArrayOutputStream()
        props.store(outputStream, null)
        val data = outputStream.toByteArray()

        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE, iv))
        val cipherText = cipher.doFinal(data)

        val byteBuffer = ByteBuffer.allocate(iv.size + cipherText.size)
        byteBuffer.put(iv)
        byteBuffer.put(cipherText)

        val tmp = File(storageDir, "secure_storage.dat.tmp")
        java.io.FileOutputStream(tmp).use { out ->
            out.write(byteBuffer.array())
            out.flush()
            out.fd.sync()
        }
        try {
            Files.move(tmp.toPath(), storageFile.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: Exception) {
            tmp.copyTo(storageFile, overwrite = true)
            tmp.delete()
        }
    }
}

actual fun createSecureStorage(platformContext: PlatformContext): SecureStorage =
    JvmSecureStorage(platformContext)
