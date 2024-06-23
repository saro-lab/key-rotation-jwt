package me.saro.jwt.core

import me.saro.jwt.exception.JwtException

interface JwtAlgorithmHash : JwtAlgorithm {
    @Throws(JwtException::class)
    fun toJwtKey(secret: String): JwtKey
}
