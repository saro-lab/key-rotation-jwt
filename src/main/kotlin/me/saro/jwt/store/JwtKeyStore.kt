//package me.saro.jwt.store
//
//import me.saro.jwt.Jwt
//import me.saro.jwt.JwtNode
//import java.time.Duration
//
//interface JwtKeyStore {
//    fun export(): String
//    fun getKeyStoreItem(): JwtKeyStoreItem
//    fun findKeyStoreItem(kid: Long): JwtKeyStoreItem
//    fun findKeyStoreItem(kid: String): JwtKeyStoreItem = findKeyStoreItem(kid.toLong())
//    fun createJwt(): JwtNode.Builder = Jwt.createJwt(getKeyStoreItem())
//    fun parseJwt(jwt: String): JwtNode = Jwt.parseJwt(jwt) { findKeyStoreItem(it.kid!!).key }
//    val keySyncTime: Duration
//    val keyExpireTime: Duration
//}