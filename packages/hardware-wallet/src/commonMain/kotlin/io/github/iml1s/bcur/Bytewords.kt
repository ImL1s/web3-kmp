package io.github.iml1s.bcur

/**
 * Bytewords encoding for Uniform Resources (UR).
 * 
 * Based on BCR-2020-012 specification:
 * - 256 unique 4-letter English words (one per byte value)
 * - First and last letters uniquely identify each word (minimal encoding)
 * - CRC32 checksum appended as 4 Bytewords
 * 
 * Ported from https://github.com/sparrowwallet/hummingbird
 */
object Bytewords {
    
    private const val BYTEWORDS = "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom"
    
    private val bytewordsList: List<String> by lazy {
        (0 until 256).map { i -> BYTEWORDS.substring(i * 4, (i * 4) + 4) }
    }
    
    private val minimalBytewordsList: List<String> by lazy {
        (0 until 256).map { i -> 
            "${BYTEWORDS[i * 4]}${BYTEWORDS[(i * 4) + 3]}"
        }
    }
    
    enum class Style {
        STANDARD,  // Space-separated full words
        URI,       // Hyphen-separated full words  
        MINIMAL    // First+last letter only (2 chars per byte)
    }
    
    /**
     * Encode binary data as Bytewords.
     * Appends CRC32 checksum automatically.
     */
    fun encode(data: ByteArray, style: Style): String {
        val dataWithChecksum = appendChecksum(data)
        
        return when (style) {
            Style.STANDARD -> dataWithChecksum.joinToString(" ") { byte ->
                bytewordsList[byte.toInt() and 0xFF]
            }
            Style.URI -> dataWithChecksum.joinToString("-") { byte ->
                bytewordsList[byte.toInt() and 0xFF]
            }
            Style.MINIMAL -> buildString {
                for (byte in dataWithChecksum) {
                    append(minimalBytewordsList[byte.toInt() and 0xFF])
                }
            }
        }
    }
    
    /**
     * Decode Bytewords string to binary data.
     * Validates and strips CRC32 checksum.
     */
    fun decode(encoded: String, style: Style): ByteArray {
        val words: List<String> = when (style) {
            Style.STANDARD -> encoded.split(" ")
            Style.URI -> encoded.split("-")
            Style.MINIMAL -> {
                val result = mutableListOf<String>()
                var i = 0
                while (i < encoded.length) {
                    result.add(encoded.substring(i, minOf(i + 2, encoded.length)))
                    i += 2
                }
                result
            }
        }
        
        val wordList = if (style == Style.MINIMAL) minimalBytewordsList else bytewordsList
        val bytes = ByteArray(words.size)
        
        for ((index, word) in words.withIndex()) {
            val byteValue = wordList.indexOf(word.lowercase())
            if (byteValue == -1) {
                throw InvalidBytewordsException("Unknown byteword: $word")
            }
            bytes[index] = byteValue.toByte()
        }
        
        return stripChecksum(bytes)
    }
    
    private fun appendChecksum(data: ByteArray): ByteArray {
        val crc = CRC32.compute(data)
        val checksum = CRC32.toBytes(crc)
        return data + checksum
    }
    
    private fun stripChecksum(dataWithChecksum: ByteArray): ByteArray {
        if (dataWithChecksum.size < 4) {
            throw InvalidChecksumException("Data too short for checksum")
        }
        
        val data = dataWithChecksum.copyOfRange(0, dataWithChecksum.size - 4)
        val providedChecksum = dataWithChecksum.copyOfRange(dataWithChecksum.size - 4, dataWithChecksum.size)
        
        val calculatedCrc = CRC32.compute(data)
        val calculatedChecksum = CRC32.toBytes(calculatedCrc)
        
        if (!providedChecksum.contentEquals(calculatedChecksum)) {
            throw InvalidChecksumException("Checksum mismatch")
        }
        
        return data
    }
    
    class InvalidBytewordsException(message: String) : RuntimeException(message)
    class InvalidChecksumException(message: String) : RuntimeException(message)
}
