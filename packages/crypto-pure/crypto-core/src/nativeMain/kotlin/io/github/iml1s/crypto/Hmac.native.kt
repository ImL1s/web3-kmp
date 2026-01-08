package io.github.iml1s.crypto

import kotlinx.cinterop.*
import platform.CoreCrypto.*

@OptIn(ExperimentalForeignApi::class)
internal actual fun platformHmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val macOut = ByteArray(32)
    val keyPtr = if (key.isNotEmpty()) key.refTo(0) else null
    val dataPtr = if (data.isNotEmpty()) data.refTo(0) else null
    CCHmac(
        kCCHmacAlgSHA256,
        keyPtr, key.size.convert(),
        dataPtr, data.size.convert(),
        macOut.refTo(0)
    )
    return macOut
}

@OptIn(ExperimentalForeignApi::class)
internal actual fun platformHmacSha512(key: ByteArray, data: ByteArray): ByteArray {
    val macOut = ByteArray(64)
    val keyPtr = if (key.isNotEmpty()) key.refTo(0) else null
    val dataPtr = if (data.isNotEmpty()) data.refTo(0) else null
    CCHmac(
        kCCHmacAlgSHA512,
        keyPtr, key.size.convert(),
        dataPtr, data.size.convert(),
        macOut.refTo(0)
    )
    return macOut
}
