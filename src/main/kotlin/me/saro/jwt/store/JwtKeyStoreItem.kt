//package me.saro.jwt.store
//
//import com.fasterxml.jackson.core.type.TypeReference
//import me.saro.jwt.Jwt
//import me.saro.jwt.JwtKey
//import me.saro.jwt.JwtUtils
//
//class JwtKeyStoreItem private constructor(
//    val kid: Long,
//    val key: JwtKey,
//    val create: Long,
//    val notBefore: Long,
//    val expire: Long
//) {
//    companion object {
//        private val trMap = object: TypeReference<Map<String, String>>() {}
//        private val trListMap = object: TypeReference<List<Map<String, String>>>() {}
//
//        fun of(kid: Long, key: JwtKey, create: Long, notBefore: Long, expire: Long): JwtKeyStoreItem =
//            JwtKeyStoreItem(kid, key, create, notBefore, expire)
//
//        fun of(kid: Long, key: String, create: Long, notBefore: Long, expire: Long): JwtKeyStoreItem =
//            JwtKeyStoreItem(kid, Jwt.parseKey(key), create, notBefore, expire)
//
//        fun of(json: String): JwtKeyStoreItem =
//            JwtUtils.readValue(json, trMap)
//                .run {
//                    JwtKeyStoreItem(
//                        kid = get("kid")!!.toLong(),
//                        key = Jwt.parseKey(get("key")!!),
//                        create = get("create")!!.toLong(),
//                        notBefore = get("notBefore")!!.toLong(),
//                        expire = get("expire")!!.toLong()
//                    )
//                }
//
//        fun ofJsonArray(jsonArray: String): List<JwtKeyStoreItem> =
//            JwtUtils.readValue(jsonArray, trListMap)
//                .map {
//                    JwtKeyStoreItem(
//                        kid = it["kid"]!!.toLong(),
//                        key = Jwt.parseKey(it["key"]!!),
//                        create = it["create"]!!.toLong(),
//                        notBefore = it["notBefore"]!!.toLong(),
//                        expire = it["expire"]!!.toLong()
//                    )
//                }
//                .sortedByDescending { it.expire }
//    }
//
//    fun toJson(): String =
//        """{"kid":$kid,"key":"${key.stringify}","create":$create,"notBefore":$notBefore,"expire":$expire}"""
//
//    override fun toString(): String = toJson()
//}