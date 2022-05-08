package me.saro.jwt.core

import me.saro.jwt.exception.JwtException

interface JwtAlgorithm {
    fun algorithm(): String

    @Throws(JwtException::class)
    fun toJwtHeader(jwt: String?): JwtHeader

    @Throws(JwtException::class)
    fun toJwtClaims(jwt: String?): JwtClaims

    fun toJwt(jwtClaims: JwtClaims, header: Map<String, Any>): String

    fun toJwt(jwtClaims: JwtClaims): String
        = toJwt(jwtClaims, mapOf())

    fun verify(jwt: String, key: JwtKey): Boolean

    fun newRandomJwtKey(): JwtKey
    fun toJwtKey(key: String): JwtKey
}
