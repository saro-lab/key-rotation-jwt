package me.saro.jwt.core

import java.nio.ByteBuffer

interface JwtAlgorithm {
    val algorithm: String
    fun toJwtKey(stringify: String): JwtKey
    fun signature(body: ByteArray, jwtKey: JwtKey): ByteArray
    fun signature(body: ByteBuffer, jwtKey: JwtKey): ByteArray
    fun verifySignature(body: ByteArray, signature: ByteArray, jwtKey: JwtKey): Boolean
    fun with(jwtKey: JwtKey): Pair<JwtAlgorithm, JwtKey> = this to jwtKey
}
