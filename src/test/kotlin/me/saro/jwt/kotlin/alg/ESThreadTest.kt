package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.es.JwtEs256
import me.saro.jwt.alg.es.JwtEs384
import me.saro.jwt.alg.es.JwtEs512
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtClaims.Companion.create
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtUtils.Companion.toJwtHeader
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*
import java.util.List

@DisplayName("[Kotlin] ES Thread And Random KID Test")
class ESThreadTest {
    @Test
    @DisplayName("Thread And Random KID Test")
    fun t1() {
        val algs = List.of(JwtEs256(), JwtEs384(), JwtEs512())
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
            val jh = toJwtHeader(jwt)
            var _alg: JwtAlgorithm? = null
            when (jh.algorithm) {
                "ES256" -> _alg = JwtEs256()
                "ES384" -> _alg = JwtEs384()
                "ES512" -> _alg = JwtEs512()
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