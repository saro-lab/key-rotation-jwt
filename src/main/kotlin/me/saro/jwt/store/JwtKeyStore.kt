package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey

interface JwtKeyStore {
    fun import(jsonArray: String): JwtKeyStore
    fun export(): String
    val key: JwtKey
    fun findKeyStoreItem(kid: Long): JwtKeyStoreItem
    fun findKeyStoreItem(kid: String): JwtKey = KeyStoreItem(kid.toLong())
    fun createJwt() = Jwt.createJwt(key)
    fun parseJwt(jwt: String) = Jwt.parseJwt(jwt) { findKey(it.kid!!) }
}