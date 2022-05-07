package me.saro.jwt.core

interface JwtKey {
    fun algorithm(): String
    fun stringify(): String
}
