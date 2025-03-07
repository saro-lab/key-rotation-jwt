package me.saro.jwt.core

interface JwtAlgorithm {
    val name: String
    val fullname: String
    fun <T: JwtKey> newRandomJwtKey(): T
    fun <T: JwtKey> toJwtKey(stringify: String): T
}
