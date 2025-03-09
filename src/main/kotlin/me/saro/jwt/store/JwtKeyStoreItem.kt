package me.saro.jwt.store

import com.fasterxml.jackson.core.type.TypeReference
import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import java.time.Instant

class JwtKeyStoreItem private constructor(
    val kid: Long,
    val key: JwtKey,
    val create: Long,
    val notBefore: Long,
    val expire: Long
) {
    companion object {
        private val trMap = object: TypeReference<Map<String, String>>() {}
        private val trListMap = object: TypeReference<List<Map<String, String>>>() {}

        fun of(kid: Long, key: JwtKey, create: Long, notBefore: Long, expire: Long): JwtKeyStoreItem =
            JwtKeyStoreItem(kid, key, create, notBefore, expire)

        fun of(kid: Long, key: String, create: Long, notBefore: Long, expire: Long): JwtKeyStoreItem =
            JwtKeyStoreItem(kid, Jwt.parseKey(key), create, notBefore, expire)

        fun of(json: String): JwtKeyStoreItem =
            JwtUtils.readValue(json, trMap)
                .run {
                    JwtKeyStoreItem(
                        get("kid")!!.toLong(),
                        Jwt.parseKey(get("key")!!),
                        get("create")!!.toLong(),
                        get("notBefore")!!.toLong(),
                        get("expire")!!.toLong()
                    )
                }

        fun ofJsonArray(jsonArray: String, removeExpired: Boolean): List<JwtKeyStoreItem> =
            JwtUtils.readValue(jsonArray, trListMap)
                .map {
                    JwtKeyStoreItem(
                        it["kid"]!!.toLong(),
                        Jwt.parseKey(it["key"]!!),
                        it["create"]!!.toLong(),
                        it["notBefore"]!!.toLong(),
                        it["expire"]!!.toLong()
                    )
                }
                .run {
                    if (removeExpired) {
                        val now: Long = Instant.now().epochSecond
                        filter { it.expire > now }
                    } else {
                        this
                    }
                }
                .sortedByDescending { it.expire }
    }

    fun toJson(): String =
        """{"kid":$kid,"key":"${key.stringify}","create":$create,"notBefore":$notBefore,"expire":$expire}"""

    override fun toString(): String = toJson()
}