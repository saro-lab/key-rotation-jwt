package me.saro.jwt.kotlin.alg

import me.saro.jwt.core.Jwt
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtClaims.Companion.create
import me.saro.jwt.core.JwtKey
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] HS Thread And Random KID Test")
class HsThreadTest {
    @Test
    @DisplayName("Thread And Random KID Test")
    fun t1() {
        val algs = listOf(Jwt.hs256(), Jwt.hs384(), Jwt.hs512())
        val keys = HashMap<String?, JwtKey>()
        val jwts = ArrayList<String>()
        for (i in 0..29) {
            val alg = algs[(Math.random() * 3).toInt()]
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey()
            keys[kid] = key
            val jc = create()
            jc.id("abc")
            jc.expire(OffsetDateTime.now().plusMinutes(30))
            jwts.add(Assertions.assertDoesNotThrow<String> { alg.toJwt(key, jc, kid) })
        }
        jwts.parallelStream().forEach { jwt: String? ->
            // use alg.toJwtHeader
            // but this case is unknown alg
            // use JwtUtils.toJwtHeader
            val jh = Jwt.toJwtHeader(jwt)
            var _alg: JwtAlgorithm? = null
            when (jh.algorithm) {
                "HS256" -> _alg = Jwt.hs256()
                "HS384" -> _alg = Jwt.hs384()
                "HS512" -> _alg = Jwt.hs512()
            }
            val alg = _alg
            Assertions.assertNotNull(alg)
            val key = keys[jh.kid]
            Assertions.assertNotNull(key)
            val jc = Assertions.assertDoesNotThrow<JwtClaims> {
                alg!!.toJwtClaims(
                    jwt!!, key
                )
            }
            Assertions.assertThrows(JwtException::class.java) {
                alg!!.toJwtClaims(
                    jwt!!, alg.newRandomJwtKey()
                )
            }
            Assertions.assertEquals(jc.id, "abc")
        }
        println("done")
    }
}