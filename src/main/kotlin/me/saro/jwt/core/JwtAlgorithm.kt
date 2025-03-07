package me.saro.jwt.core

interface JwtAlgorithm {
    val algorithm: String
    fun <T: JwtKey> newRandomJwtKey(): T
    fun <T: JwtKey> toJwtKey(stringify: String): T
}
