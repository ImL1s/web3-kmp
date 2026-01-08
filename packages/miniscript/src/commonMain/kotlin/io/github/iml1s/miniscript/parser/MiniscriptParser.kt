package io.github.iml1s.miniscript.parser

/**
 * A generic tree structure representing a parsed Miniscript expression.
 *
 * @property name The name of the node (e.g., "pk", "and_v", "c:pk_k").
 * @property children The list of child nodes.
 */
data class TokenTree(
    val name: String,
    val children: List<TokenTree> = emptyList()
) {
    override fun toString(): String {
        if (children.isEmpty()) return name
        return "$name(${children.joinToString(",")})"
    }
}

class MiniscriptParser {
    companion object {
        fun parse(input: String): TokenTree {
            return Parser(input).parse()
        }

        private fun parseNode(iterator: Iterator<String>): TokenTree {
            if (!iterator.hasNext()) throw IllegalArgumentException("Unexpected end of input")
            val name = iterator.next()
            
            // Check if there are children (lookahead logic simulated)
            // Since we can't easily peek with standard Iterator, we might need a richer tokenizer
            // or a PeekableIterator. Let's refine the logic.
            return TokenTree(name) // Placeholder, need better logic below
        }

        private fun tokenize(input: String): List<String> {
            // This is a naive tokenizer. We need to handle '(', ')', ',' as separate tokens
            // but keep alphanumeric strings together.
            return input.replace("(", " ( ")
                .replace(")", " ) ")
                .replace(",", " , ")
                .split("\\s+".toRegex())
                .filter { it.isNotEmpty() }
        }
    }
}

/**
 * Improved Parser Implementation
 */
private class Parser(private val input: String) {
    private var pos = 0

    fun parse(): TokenTree {
        val root = parseExpression()
        if (pos < input.length) {
            throw IllegalArgumentException("Unexpected characters at index $pos: '${input.substring(pos)}'")
        }
        return root
    }

    private fun parseExpression(): TokenTree {
        skipWhitespace()
        
        // Handle Brace group { ... }
        if (pos < input.length && input[pos] == '{') {
            consume('{')
            val children = mutableListOf<TokenTree>()
            while (pos < input.length && input[pos] != '}') {
                children.add(parseExpression())
                skipWhitespace()
                if (pos < input.length && input[pos] == ',') {
                    consume(',')
                } else {
                    break
                }
            }
            consume('}')
            return TokenTree("{", children)
        }

        val start = pos
        while (pos < input.length && isNameChar(input[pos])) {
            pos++
        }
        val name = input.substring(start, pos)
        if (name.isEmpty()) throw IllegalArgumentException("Expected name at index $pos")

        skipWhitespace()
        val children = mutableListOf<TokenTree>()
        if (pos < input.length && input[pos] == '(') {
            consume('(')
            while (pos < input.length && input[pos] != ')') {
                children.add(parseExpression())
                skipWhitespace()
                if (pos < input.length && input[pos] == ',') {
                    consume(',')
                } else {
                    break
                }
            }
            consume(')')
        }
        return TokenTree(name, children)
    }

    private fun isNameChar(c: Char): Boolean {
        return c.isLetterOrDigit() || c == '_' || c == ':' || c == '@' || c == '#' || c == '/' || c == '*' || c == '+' || c == '-' || c == '[' || c == ']'
    }

    private fun skipWhitespace() {
        while (pos < input.length && input[pos].isWhitespace()) {
            pos++
        }
    }

    private fun consume(char: Char) {
        if (pos >= input.length || input[pos] != char) {
            throw IllegalArgumentException("Expected '$char' at index $pos, found '${if (pos < input.length) input[pos] else "EOF"}'")
        }
        pos++
    }
}

fun parseMiniscript(input: String): TokenTree {
    return Parser(input).parse()
}
