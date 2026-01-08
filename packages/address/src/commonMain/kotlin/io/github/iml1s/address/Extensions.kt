package io.github.iml1s.address

/**
 * Minimal format extension for String to support hex formatting in commonMain
 */
internal fun String.format(vararg args: Any?): String {
    if (this == "%02x" && args.size == 1) {
        val byte = args[0] as? Byte ?: return "00"
        val intValue = byte.toInt() and 0xFF
        val chars = "0123456789abcdef"
        return "${chars[(intValue shr 4) and 0x0F]}${chars[intValue and 0x0F]}"
    }
    if (this == "%08x" && args.size == 1) {
        val long = args[0] as? Long ?: (args[0] as? Int)?.toLong() ?: return "00000000"
        val chars = "0123456789abcdef"
        var result = ""
        for (i in 7 downTo 0) {
            val nibble = (long shr (i * 4)) and 0x0F
            result += chars[nibble.toInt()]
        }
        return result
    }
    
    // Basic fallback replacement for other cases
    var result = this
    args.forEachIndexed { index, arg ->
        result = result.replace("%${index + 1}", arg.toString())
        result = result.replace("%s", arg.toString())
    }
    return result
}

internal fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }
