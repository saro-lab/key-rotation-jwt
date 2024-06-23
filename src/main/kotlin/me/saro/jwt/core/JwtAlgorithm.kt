package me.saro.jwt.core

import me.saro.jwt.exception.JwtException

interface JwtAlgorithm {
    fun algorithm(): String

    fun newRandomJwtKey(): JwtKey

    @Throws(JwtException::class)
    fun signature(body: String, jwtKey: JwtKey): String

    fun defaultHeader(): Map<String, Any> =
        mapOf("TYP" to "JWT", "alg" to algorithm())

    @Throws(JwtException::class)
    fun toJwtHeader(jwt: String?): JwtHeader =
        Jwt.toJwtHeader(jwt)

    @Throws(JwtException::class)
    fun toJwt(jwtKey: JwtKey, claims: JwtClaims): String =
        toJwt(jwtKey, claims, mapOf())

    @Throws(JwtException::class)
    fun toJwt(jwtKey: JwtKey, claims: JwtClaims, kid: String): String =
        toJwt(jwtKey, claims, mapOf("kid" to kid))

    @Throws(JwtException::class)
    fun toJwt(jwtKey: JwtKey, claims: JwtClaims, appendHeader: Map<String, Any>): String =
        Jwt
            .toJwtData(this.defaultHeader() + appendHeader, claims.toMap())
            .let { body -> StringBuilder(512).append(body).append('.').append(signature(body, jwtKey)).toString() }

    @Throws(JwtException::class)
    fun toJwtClaimsWithoutVerify(jwt: String?): JwtClaims =
        Jwt.toJwtClaimsWithoutVerify(jwt)

    fun toJwtClaimsOrNull(jwt: String, jwtKey: JwtKey): JwtClaims? =
        try { toJwtClaims(jwt, jwtKey) } catch (e: Exception) { null }

    @Throws(JwtException::class)
    fun toJwtClaims(jwt: String, jwtKey: JwtKey?): JwtClaims
}
