package me.saro.jwt

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import java.util.concurrent.ConcurrentHashMap

class JwtKidManager<KID>(
    private val jwtAlgorithm: JwtAlgorithm,
    private val jwtKeyMap: ConcurrentHashMap<KID, JwtKey>,
    private val newJwtIoKeyPicker: (Map<KID, JwtKey>) -> Pair<KID, JwtKey>
) {

    fun addKey(kid: KID, jwtKey: JwtKey) {
        jwtKeyMap[kid] = jwtKey
    }

    fun delKey(kid: KID?) {
        jwtKeyMap.remove(kid)
    }

    fun delKeyIf(filter: (KID, JwtKey) -> Boolean) {
        for ((kid, key) in jwtKeyMap) {
            if (filter(kid, key)) {
                jwtKeyMap.remove(kid!!)
            }
        }
    }

    fun setKeyMap(map: Map<KID, JwtKey>) {
        val ids = map.keys
        map.forEach { (id, jwtKey) -> addKey(id, jwtKey) }
        delKeyIf { id, _ -> !ids.contains(id) }
    }

    fun createJwtIo() =
        JwtObject.create(jwtAlgorithm.algorithm())

    fun toJwt(jwtObject: JwtObject): String {
        val pair = newJwtIoKeyPicker(jwtKeyMap)
        jwtObject.header("kid", pair.first as Any)
        val body = jwtObject.toJwtBody()
        return body + "." + jwtAlgorithm.signature(pair.second, body)
    }


    fun toJwtIo(jwt: String): JwtObject {
        val jwtObject = JwtObject.parse(jwt)

        val kid = jwtObject.kid()
            ?: throw JwtException("dose not exist kid field")

        @Suppress("UNCHECKED_CAST")
        val key = jwtKeyMap[kid as KID]
            ?: throw JwtException("not found key[kid=$kid]")

        return jwtAlgorithm.verify(key, jwt, jwtObject)
    }
}