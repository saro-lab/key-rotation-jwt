package me.saro.jwt.kotlin.alg

import me.saro.jwt.core.*
import me.saro.jwt.core.JwtClaims.Companion.create
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] RS Thread And Random KID Test")
class RsThreadTest {

    fun randomKeyBit() = listOf(2048, 3072, 4096)[(Math.random() * 3).toInt()]

    @Test
    @DisplayName("Thread And Random KID Test")
    fun t1() {
        val algs = listOf(Jwt.rs256(), Jwt.rs384(), Jwt.rs512())
        val keys = HashMap<String?, JwtKey>()
        val jwts = ArrayList<String>()
        for (i in 0..29) {
            val alg = algs[(Math.random() * 3).toInt()]
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey(randomKeyBit())
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
            var _alg: JwtAlgorithmPemKeyPair? = null
            when (jh.algorithm) {
                "RS256" -> _alg = Jwt.rs256()
                "RS384" -> _alg = Jwt.rs384()
                "RS512" -> _alg = Jwt.rs512()
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
                    jwt!!, alg.newRandomJwtKey(randomKeyBit())
                )
            }
            Assertions.assertEquals(jc.id, "abc")
        }
        println("done")
    }
}