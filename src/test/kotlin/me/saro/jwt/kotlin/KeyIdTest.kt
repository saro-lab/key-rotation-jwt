package me.saro.jwt.kotlin

import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.parseJwt
import me.saro.jwt.Jwt.Companion.parseKey
import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtNode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] Key ID test")
class KeyIdTest {
    @Test
    @DisplayName("[Kotlin] Key ID test")
    fun kid() {
        // create string key list
        val stringKeyMap = createKeyId(
            3,
            Jwt.ES256,
            Jwt.ES384,
            Jwt.ES512,
            Jwt.HS256,
            Jwt.HS384,
            Jwt.HS512,
            Jwt.PS256,
            Jwt.PS384,
            Jwt.PS512,
            Jwt.RS256,
            Jwt.RS384,
            Jwt.RS512
        )
        // convert string key list to key list
        val keyMap = convertKeyId(stringKeyMap)

        // create jwts
        var start = System.currentTimeMillis()
        val jwtList: MutableList<String> = ArrayList()
        keyMap.forEach { (kid: String?, key: JwtKey?) ->
            for (i in 0..9) {
                val jwt = key.newJwtBuilder()
                    .kid(kid!!)
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .toJwt()
                jwtList.add(jwt)
            }
        }
        println("create " + jwtList.size + " jwts - " + (System.currentTimeMillis() - start) + "ms")

        // parse jwts
        start = System.currentTimeMillis()
        for (jwt in jwtList) {
            val node = Assertions.assertDoesNotThrow<JwtNode> {
                parseJwt(jwt) { e: JwtNode ->
                    keyMap[e.kid]
                }
            }
            Assertions.assertEquals("1234567890", node.subject)
            Assertions.assertEquals("John Doe", node.claimString("name"))
            Assertions.assertEquals(true, node.claimBoolean("admin"))
            Assertions.assertEquals(1516239022, node.claimInt("iat"))
        }
        println("parse " + jwtList.size + " jwts - " + (System.currentTimeMillis() - start) + "ms")
    }

    fun createKeyId(loop: Int, vararg algs: JwtAlgorithm): Map<String, String> {
        val keyMap: MutableMap<String, String> = HashMap()
        val start = System.currentTimeMillis()
        var kid = System.currentTimeMillis()
        for (alg in algs) {
            for (i in 0..<loop) {
                keyMap[(kid++).toString()] = alg.newRandomJwtKey().stringify
            }
        }
        keyMap.forEach { (k: String?, key: String?) ->
            println("$k : $key")
        }
        println("create String keys " + (loop * algs.size) + " keys - " + (System.currentTimeMillis() - start) + "ms")
        return keyMap
    }

    fun convertKeyId(stringJwtKeyMap: Map<String, String>): Map<String?, JwtKey> {
        val keyMap: MutableMap<String?, JwtKey> = HashMap()
        val start = System.currentTimeMillis()

        stringJwtKeyMap.forEach { (kid: String?, key: String?) ->
            keyMap[kid] = parseKey(key)
        }

        println("convert " + keyMap.size + " String keys - " + (System.currentTimeMillis() - start) + "ms")

        return keyMap
    }
}
