package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentLinkedDeque

interface JwtKeyStore {
    fun import(jsonArray: String): JwtKeyStore
    fun export(): String
    fun nowKey(): JwtKey
    fun findKey(kid: String): JwtKey
    fun createJwt() = Jwt.createJwt(nowKey())
    fun parseJwt(jwt: String) = Jwt.parseJwt(jwt) { findKey(it.kid!!) }

    companion object {
        class Builder {
            private var initList: Collection<JwtKeyStoreItem> = listOf()

            fun build(): JwtKeyStore {
                val now = OffsetDateTime.now().toEpochSecond()
                initList.stream().filter { it.expire > now }
                return JwtKeyStore(ConcurrentLinkedDeque(initList))
            }
        }
    }
}