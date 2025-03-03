package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.core.Jwt
import me.saro.jwt.core.Jwt.Companion.builder
import me.saro.jwt.core.Jwt.Companion.parse
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtNode
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] HS256")
class Hs256 {
    var alg: JwtHs256 = Jwt.HS256

    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val jwt =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        val secret = "your-256-bit-secret"
        val key = alg.toJwtKey(secret)

        println("example")
        Assertions.assertDoesNotThrow<JwtNode> { parse(jwt) { node: JwtNode? -> alg.with(key) } }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(
            JwtException::class.java
        ) { parse(jwt) { node: JwtNode? -> alg.with(alg.newRandomJwtKey()) } }
        println("example jwt error text - pass")
    }

    @Test
    @DisplayName("kid test")
    fun t2() {
        val keys = HashMap<String?, JwtKey>()
        val jwtList = ArrayList<String>()

        for (i in 0..29) {
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey()
            keys[kid] = key

            jwtList.add(Assertions.assertDoesNotThrow<String> {
                builder()
                    .kid(kid)
                    .id("abc")
                    .expire(OffsetDateTime.now().plusMinutes(30))
                    .toJwt(alg, key)
            })
        }

        jwtList.parallelStream().forEach { jwt: String? ->
            Assertions.assertThrows(
                JwtException::class.java
            ) { parse(jwt) { node: JwtNode? -> alg.with(alg.newRandomJwtKey()) } }
            println(jwt)
            val jwtNode = Assertions.assertDoesNotThrow<JwtNode> {
                parse(jwt) { node: JwtNode ->
                    alg.with(
                        keys[node.kid]!!
                    )
                }
            }
            Assertions.assertEquals("abc", jwtNode.id)
        }
        println("done")
    }

    @Test
    @DisplayName("expire test")
    fun t3() {
        val key = alg.newRandomJwtKey()

        val jwtPass = builder().expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key)
        Assertions.assertDoesNotThrow<JwtNode> {
            parse(jwtPass) { node: JwtNode? ->
                alg.with(
                    key
                )
            }
        }

        val jwtFail = builder().expire(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key)
        Assertions.assertThrowsExactly(
            JwtException::class.java
        ) { parse(jwtFail) { node: JwtNode? -> alg.with(key) } }
    }

    @Test
    @DisplayName("not before test")
    fun t4() {
        val key = alg.newRandomJwtKey()

        val jwtPass = builder().notBefore(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key)
        Assertions.assertDoesNotThrow<JwtNode> {
            parse(jwtPass) { node: JwtNode? ->
                alg.with(
                    key
                )
            }
        }

        val jwtFail = builder().notBefore(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key)
        Assertions.assertThrowsExactly(
            JwtException::class.java
        ) { parse(jwtFail) { node: JwtNode? -> alg.with(key) } }
    }

    @Test
    @DisplayName("data test")
    fun t5() {
        val key = alg.newRandomJwtKey()

        val jwt = builder()
            .issuedAt(OffsetDateTime.now())
            .notBefore(OffsetDateTime.now().minusMinutes(1))
            .expire(OffsetDateTime.now().plusMinutes(30))
            .id("jti value")
            .issuer("iss value")
            .subject("sub value")
            .audience("aud value")
            .claim("custom", "custom value")
            .toJwt(alg, key)

        println(jwt)

        val jwtNode = Assertions.assertDoesNotThrow<JwtNode> {
            parse(jwt) { node: JwtNode? ->
                alg.with(
                    key
                )
            }
        }

        println(jwtNode)

        Assertions.assertEquals("jti value", jwtNode.id)
        Assertions.assertEquals("iss value", jwtNode.issuer)
        Assertions.assertEquals("sub value", jwtNode.subject)
        Assertions.assertEquals("aud value", jwtNode.audience)
        Assertions.assertEquals("custom value", jwtNode.claim("custom"))
    }
}
