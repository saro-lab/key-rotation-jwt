package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode

interface JwtAlgorithmHash : JwtAlgorithm {
    companion object {
        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
        private val MOLD_LEN = MOLD.size
    }

    @Throws(JwtException::class)
    fun toJwtKey(secret: String): JwtKey

    override fun toJwtKeyByStringify(stringify: String): JwtKey = toJwtKey(stringify)

    fun newRandomJwtKey(): JwtKey =
        newRandomJwtKey(32, 64)

    fun newRandomJwtKey(minLength: Int, maxLength: Int): JwtKey {
        if (minLength > maxLength) {
            throw IllegalArgumentException("maxLength must be greater than minLength")
        }
        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
        }
        return toJwtKey(chars.toString())
    }

    @Throws(JwtException::class)
    override fun toJwtClaims(jwt: String, jwtKey: JwtKey?): JwtClaims {
        jwtKey ?: throw JwtException(JwtExceptionCode.INVALID_KEY)
        toJwtHeader(jwt).validAlgorithm(algorithm())
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            if (signature(jwt.substring(0, lastPoint), jwtKey) == jwt.substring(lastPoint + 1)) {
                return Jwt.toJwtClaimsWithoutVerify(jwt).apply { valid() }
            } else {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
        } else {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}
