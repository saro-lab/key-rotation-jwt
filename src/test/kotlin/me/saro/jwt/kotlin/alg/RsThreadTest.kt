package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.rs.JwtRsAlgorithm
import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.builder
import me.saro.jwt.Jwt.Companion.parse
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtNode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] RS Thread And Random KID Test")
class RsThreadTest {
    fun randomKeyBit(): Int {
        return listOf(2048, 3072, 4096)[(Math.random() * 3).toInt()]
    }

    @Test
    @DisplayName("Thread And Random KID Test")
    fun t1() {
        val algs = listOf(Jwt.RS256, Jwt.RS384, Jwt.RS512)
        val algMap: Map<String?, JwtAlgorithm> = algs.stream().collect(
            { HashMap() },
            { m: HashMap<String?, JwtAlgorithm>, a: JwtRsAlgorithm -> m[a.fullname] = a },
            { obj: HashMap<String?, JwtAlgorithm>, m: HashMap<String?, JwtAlgorithm>? ->
                obj.putAll(
                    m!!
                )
            })
        val keys = HashMap<String?, JwtKey>()
        val jwts = ArrayList<String>()

        for (i in 0..29) {
            val alg = algs[(Math.random() * 3).toInt()]
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey(randomKeyBit())
            keys[kid] = key
            jwts.add(Assertions.assertDoesNotThrow<String> {
                builder().kid(kid).id("abc").expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key)
            })
        }

        jwts.parallelStream().map { jwt: String? ->
            Assertions.assertDoesNotThrow<JwtNode> {
                parse(jwt) { node: JwtNode ->
                    val alg = algMap[node.algorithm]
                    val key = keys[node.kid]
                    alg!!.with(key!!)
                }
            }
        }.forEach { JwtNode: JwtNode -> Assertions.assertEquals("abc", JwtNode.id) }
        println("done")
    }
}
