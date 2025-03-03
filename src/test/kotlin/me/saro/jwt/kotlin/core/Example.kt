package me.saro.jwt.kotlin.core

import me.saro.jwt.alg.es.JwtEs256
import me.saro.jwt.core.Jwt
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtNode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] example")
class Example {
    var alg: JwtEs256 = Jwt.ES256

    @Test
    @DisplayName("basic")
    fun t1() {
        val key = alg.newRandomJwtKey()

        val jwtNode: JwtNode.Builder = Jwt.builder()
            .issuedAt(OffsetDateTime.now())
            .notBefore(OffsetDateTime.now().minusMinutes(1))
            .expire(OffsetDateTime.now().plusMinutes(30))
            .id("jti value")
            .issuer("iss value")
            .subject("sub value")
            .audience("aud value")
            .claim("custom", "custom value")

        println(jwtNode)

        val jwt: String = Assertions.assertDoesNotThrow<String> { jwtNode.toJwt(alg, key) }

        println(jwt)

        val readJwtNode = Assertions.assertDoesNotThrow<JwtNode> {
            Jwt.parse(jwt) { alg.with(key) }
        }

        println(readJwtNode)

        Assertions.assertEquals("jti value", readJwtNode.id)
        Assertions.assertEquals("iss value", readJwtNode.issuer)
        Assertions.assertEquals("sub value", readJwtNode.subject)
        Assertions.assertEquals("aud value", readJwtNode.audience)
        Assertions.assertEquals("custom value", readJwtNode.claim("custom"))
    }

    @Test
    @DisplayName("dynamic key")
    fun t2() {
        val keyMap = HashMap<String?, JwtKey>()
        val jwtList = ArrayList<String>()

        // make keys
        for (i in 0..29) {
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey()
            keyMap[kid] = key
        }

        // make jwt list with random key
        for (i in 0..9) {
            val jwtNode: JwtNode.Builder = Jwt.builder()
                .issuedAt(OffsetDateTime.now())
                .notBefore(OffsetDateTime.now().minusMinutes(1))
                .expire(OffsetDateTime.now().plusMinutes(30))
                .id("jti value $i")
                .issuer("iss value $i")
                .subject("sub value $i")
                .audience("aud value $i")
                .claim("custom", "custom value $i")

            val randomKid = keyMap.keys.toTypedArray()[(Math.random() * keyMap.size).toInt()] as String
            val randomKey = keyMap[randomKid]

            // make jwt with key / kid(header)
            val jwt = Assertions.assertDoesNotThrow<String> {
                jwtNode.kid(randomKid).toJwt(alg, randomKey!!)
            }
            jwtList.add(jwt)
        }

        // decode
        for (i in 0..9) {
            val jwt = jwtList[i]

            println()
            println("jwt : $jwt")

            val readJwtNode = Assertions.assertDoesNotThrow<JwtNode> {
                Jwt.parse(jwt) { alg.with(keyMap[it.kid]!!) }
            }

            Assertions.assertEquals(readJwtNode.id, "jti value $i")
            Assertions.assertEquals(readJwtNode.issuer, "iss value $i")
            Assertions.assertEquals(readJwtNode.subject, "sub value $i")
            Assertions.assertEquals(readJwtNode.audience, "aud value $i")
            Assertions.assertEquals(readJwtNode.claim("custom"), "custom value $i")
        }
    }
}
