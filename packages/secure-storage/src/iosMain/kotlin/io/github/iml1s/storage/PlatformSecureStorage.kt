@file:OptIn(ExperimentalForeignApi::class)
package io.github.iml1s.storage

import kotlinx.cinterop.*
import platform.Foundation.*
import platform.Security.*
import platform.CoreFoundation.*
import platform.darwin.NSObject

/**
 * iOS implementation of PlatformContext (placeholder)
 */
actual class PlatformContext

/**
 * iOS implementation of SecureStorage using Keychain Services.
 * Uses manual CFDictionary construction to avoid ClassCastException and ensure compatibility.
 */
class IosSecureStorage(platformContext: PlatformContext) : SecureStorage {

    override suspend fun put(key: String, value: String) {
        memScoped {
            val data = NSString.create(string = value).dataUsingEncoding(NSUTF8StringEncoding)!!
            
            val query = CFDictionaryCreateMutable(null, 4, null, null)
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(NSString.create(string = key)))
            CFDictionaryAddValue(query, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlock)
            CFDictionaryAddValue(query, kSecValueData, CFBridgingRetain(data))

            val status = SecItemAdd(query?.reinterpret(), null)
            // println("DEBUG: SecItemAdd status=$status")
            
            if (status == errSecDuplicateItem) {
                val updateQuery = CFDictionaryCreateMutable(null, 2, null, null)
                CFDictionaryAddValue(updateQuery, kSecClass, kSecClassGenericPassword)
                CFDictionaryAddValue(updateQuery, kSecAttrAccount, CFBridgingRetain(NSString.create(string = key)))

                val attributesToUpdate = CFDictionaryCreateMutable(null, 1, null, null)
                CFDictionaryAddValue(attributesToUpdate, kSecValueData, CFBridgingRetain(data))

                SecItemUpdate(updateQuery?.reinterpret(), attributesToUpdate?.reinterpret())
            }
        }
    }

    override suspend fun get(key: String): String? = memScoped {
        val query = CFDictionaryCreateMutable(null, 4, null, null)
        CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
        CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(NSString.create(string = key)))
        CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue)
        CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne)

        val resultRef = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query?.reinterpret(), resultRef.ptr)
        
        if (status == errSecSuccess) {
            val data = resultRef.value?.let { CFBridgingRelease(it) } as? NSData
            data?.let { 
                NSString.create(data = it, encoding = NSUTF8StringEncoding) 
            } as String?
        } else {
            null
        }
    }

    override suspend fun delete(key: String) {
        memScoped {
            val query = CFDictionaryCreateMutable(null, 2, null, null)
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionaryAddValue(query, kSecAttrAccount, CFBridgingRetain(NSString.create(string = key)))
            SecItemDelete(query?.reinterpret())
        }
    }

    override suspend fun clear() {
        memScoped {
            val query = CFDictionaryCreateMutable(null, 1, null, null)
            CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword)
            SecItemDelete(query?.reinterpret())
        }
    }
}

actual fun createSecureStorage(platformContext: PlatformContext): SecureStorage = 
    IosSecureStorage(platformContext)
