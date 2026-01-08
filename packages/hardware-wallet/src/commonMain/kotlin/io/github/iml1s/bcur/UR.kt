package io.github.iml1s.bcur

/**
 * Uniform Resource (UR) representation.
 * 
 * Based on BCR-2020-005 specification:
 * - URI scheme: "ur:<type>/<data>" for single-part
 * - URI scheme: "ur:<type>/<seq>/<fragment>" for multi-part
 * - Data is CBOR encoded and then Bytewords encoded
 * 
 * Ported from https://github.com/sparrowwallet/hummingbird
 */
data class UR(
    val type: String,
    val cborData: ByteArray
) {
    init {
        require(isValidType(type)) { "Invalid UR type: $type" }
    }
    
    companion object {
        const val UR_PREFIX = "ur"
        
        /**
         * Validate UR type string.
         * Type must contain only lowercase letters, digits, and hyphens.
         */
        fun isValidType(type: String): Boolean {
            if (type.isEmpty()) return false
            return type.all { c ->
                c in 'a'..'z' || c in '0'..'9' || c == '-'
            }
        }
        
        /**
         * Parse a UR string into its components.
         * Supports both single-part and multi-part URs.
         */
        fun parse(urString: String): UR {
            val lowered = urString.lowercase()
            
            // Check UR prefix
            if (!lowered.startsWith("$UR_PREFIX:")) {
                throw InvalidURException("UR must start with 'ur:'")
            }
            
            val pathComponents = lowered.substringAfter("$UR_PREFIX:").split("/")
            if (pathComponents.isEmpty()) {
                throw InvalidURException("UR must have a type")
            }
            
            val type = pathComponents[0]
            if (!isValidType(type)) {
                throw InvalidURException("Invalid UR type: $type")
            }
            
            return when (pathComponents.size) {
                2 -> {
                    // Single-part UR: ur:<type>/<message>
                    val messageEncoded = pathComponents[1]
                    val cborData = Bytewords.decode(messageEncoded, Bytewords.Style.MINIMAL)
                    UR(type, cborData)
                }
                3 -> {
                    // Multi-part UR: ur:<type>/<seq>/<fragment>
                    // For decoding multi-part, use URDecoder
                    throw InvalidURException("Use URDecoder for multi-part URs")
                }
                else -> throw InvalidURException("Invalid UR path structure")
            }
        }
    }
    
    /**
     * Encode single-part UR to string.
     */
    fun encode(): String {
        val encodedData = Bytewords.encode(cborData, Bytewords.Style.MINIMAL)
        return "$UR_PREFIX:$type/$encodedData"
    }
    
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false
        
        other as UR
        return type == other.type && cborData.contentEquals(other.cborData)
    }
    
    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + cborData.contentHashCode()
        return result
    }
    
    override fun toString(): String = encode()
    
    class InvalidURException(message: String) : RuntimeException(message)
}
