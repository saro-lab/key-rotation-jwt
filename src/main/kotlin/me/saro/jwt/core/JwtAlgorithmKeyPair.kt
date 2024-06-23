package me.saro.jwt.core

import me.saro.jwt.exception.JwtException

interface JwtAlgorithmKeyPair : JwtAlgorithm {
    @Throws(JwtException::class)
    fun toJwtKey(publicKey: String, privateKey: String): JwtKey
}
