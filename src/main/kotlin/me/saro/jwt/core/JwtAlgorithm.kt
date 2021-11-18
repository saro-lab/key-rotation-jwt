package me.saro.jwt.core

import java.util.function.Function

interface JwtAlgorithm {

    fun toJwtObjectWithVerify(jwt: String, searchJwtKey: Function<Any?, JwtKey>): JwtObject

    fun toJwtObjectWithVerify(jwt: String, jwtKey: JwtKey): JwtObject =
        toJwtObjectWithVerify(jwt) { jwtKey }

    fun toJwtObjectWithVerifyOrNull(jwt: String, searchJwtKey: Function<Any?, JwtKey>): JwtObject? =
        try { toJwtObjectWithVerify(jwt, searchJwtKey) } catch (e: Exception) { null }

    fun toJwtObjectWithVerifyOrNull(jwt: String, jwtKey: JwtKey): JwtObject? =
        try { toJwtObjectWithVerify(jwt) { jwtKey } } catch (e: Exception) { null }

    fun verify(jwt: String, jwtKey: JwtKey): Boolean =
        toJwtObjectWithVerifyOrNull(jwt, jwtKey) != null

    fun algorithm(): String
    fun signature(body: String, jwtKey: JwtKey): String

    fun randomJwtKey(): JwtKey
    fun parseJwtKey(keyData: String): JwtKey

    fun createJwtObject(): JwtObject =
        JwtObject.create(algorithm())

    fun toJwt(jwtObject: JwtObject, jwtKey: JwtKey): String =
        jwtObject.toJwtBody().run { this + '.' + signature(this, jwtKey) }
}
