package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*

interface JwtAlgorithm {
    fun algorithm(): String

    fun newRandomJwtKey(): JwtKey

    @Throws(JwtException::class)
    fun signature(body: String, key: JwtKey): String

    @Throws(JwtException::class)
    fun toJwtKey(key: String): JwtKey

    // default

    fun defaultHeader(): Map<String, Any> =
        mapOf("TYP" to "JWT", "alg" to algorithm())

    @Throws(JwtException::class)
    fun toJwtHeader(jwt: String?): JwtHeader =
        JwtUtils.toJwtHeader(jwt)

    @Throws(JwtException::class)
    fun toJwt(key: JwtKey, claims: JwtClaims) =
        toJwt(key, claims, mapOf())

    @Throws(JwtException::class)
    fun toJwt(key: JwtKey, claims: JwtClaims, kid: String) =
        toJwt(key, claims, mapOf("kid" to kid))

    @Throws(JwtException::class)
    fun toJwt(key: JwtKey, claims: JwtClaims, appendHeader: Map<String, Any>): String =
        JwtUtils
            .toJwtData(this.defaultHeader() + appendHeader, claims.toMap())
            .let { body -> StringBuilder(512).append(body).append('.').append(signature(body, key)).toString() }

    @Throws(JwtException::class)
    fun toJwtClaimsWithoutVerify(jwt: String?): JwtClaims =
        JwtUtils.toJwtClaimsWithoutVerify(jwt)

    fun toJwtClaimsOrNull(jwt: String, key: JwtKey): JwtClaims? =
        try { toJwtClaims(jwt, key) } catch (e: Exception) { null }

    @Throws(JwtException::class)
    fun toJwtClaims(jwt: String, key: JwtKey?): JwtClaims {
        val header = toJwtHeader(jwt)
        if (key == null) {
            throw JwtException(JwtExceptionCode.JWT_KEY_IS_NULL)
        }
        if (header.algorithm != algorithm()) {
            throw JwtException(JwtExceptionCode.NOT_EQUALS_HEADER_ALGORITHM)
        }
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            if (signature(jwt.substring(0, lastPoint), key) == jwt.substring(lastPoint + 1)) {
                val claims = JwtUtils.toJwtClaimsWithoutVerify(jwt)
                if (claims.expire() != null && claims.expire()!!.before(Date())) {
                    throw JwtException(JwtExceptionCode.DATE_EXPIRED)
                }
                return claims
            } else {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
        } else {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}
