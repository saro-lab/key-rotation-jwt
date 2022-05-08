package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode

class JwtHeader(
    private val header: Map<String, Any>
) {
    companion object {
        @JvmStatic
        fun create(algorithm: String): JwtHeader =
            JwtHeader(mapOf("typ" to "JWT", "alg" to algorithm))

        @JvmStatic
        fun create(algorithm: String, kid: Any): JwtHeader =
            JwtHeader(mapOf("typ" to "JWT", "alg" to algorithm, "kid" to kid))
    }

    val kid: String? get() = get("kid") as String?

    val type: String? get() = get("typ") as String?

    val algorithm: String? get() = get("alg") as String?

    fun get(key: String): Any? = header[key]

    fun toMap(): MutableMap<String, Any> = header.toMutableMap()

    override fun toString(): String = JwtUtils.toJsonString(header)

    @Throws(JwtException::class)
    fun assertAlgorithm(algorithm: String) {
        if (this.algorithm != algorithm) {
            throw JwtException(JwtExceptionCode.NOT_EQUALS_HEADER_ALGORITHM)
        }
    }
}
