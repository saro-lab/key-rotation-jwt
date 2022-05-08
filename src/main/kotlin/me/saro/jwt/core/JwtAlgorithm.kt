package me.saro.jwt.core

import me.saro.jwt.exception.JwtException

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
    fun toJwtClaims(jwt: String, key: JwtKey?): JwtClaims
}
