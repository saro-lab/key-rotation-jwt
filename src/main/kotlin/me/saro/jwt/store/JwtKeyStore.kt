package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtNode

interface JwtKeyStore {
    fun export(): String
    fun getKey(): JwtKey
    fun findKey(kid: String): JwtKey
    fun createJwt(): JwtNode.Builder = Jwt.createJwt(getKey())
    fun parseJwt(jwt: String): JwtNode = Jwt.parseJwt(jwt) { findKey(it.kid!!) }
}
