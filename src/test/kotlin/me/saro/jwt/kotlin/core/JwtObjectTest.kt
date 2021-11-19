package me.saro.jwt.kotlin.core

import me.saro.jwt.alg.es.JwtEs256
import me.saro.jwt.alg.es.JwtEs384
import me.saro.jwt.alg.es.JwtEs512
import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.alg.hs.JwtHs384
import me.saro.jwt.alg.hs.JwtHs512
import me.saro.jwt.core.JwtAlgorithm
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.text.ParseException
import java.text.SimpleDateFormat

@DisplayName("[Kotlin] JwtObject")
class JwtObjectTest {
    @Test
    @DisplayName("input / output")
    fun t1() {
        jwtObjectTest(JwtEs256())
        jwtObjectTest(JwtEs384())
        jwtObjectTest(JwtEs512())
        jwtObjectTest(JwtHs256())
        jwtObjectTest(JwtHs384())
        jwtObjectTest(JwtHs512())
    }

    private fun jwtObjectTest(alg: JwtAlgorithm) {
        val simpleDateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")

        val jwtObject = alg.createJwtObject()
        val jwtKey = alg.randomJwtKey()

        jwtObject.header("h1", "v1")
        jwtObject.header("h2", "v2")
        jwtObject.header("h3", "v3")

        jwtObject.kid("kid1")

        jwtObject.audience("aud1")
        jwtObject.id("id2")
        jwtObject.issuer("iss3")
        jwtObject.subject("sub4")

        jwtObject.issuedAt(simpleDateFormat.parse("1988-01-01 03:01:32"))
        jwtObject.notBefore(simpleDateFormat.parse("2000-03-11 03:22:11"))
        jwtObject.expire(simpleDateFormat.parse("2999-12-31 00:00:00"))

        jwtObject.claim("c1", "v1")
        jwtObject.claim("c2", "v2")
        jwtObject.claim("c3", "v3")

        println(jwtObject)

        val jwt = alg.toJwt(jwtObject, jwtKey)
        println(jwt)

        val jwtObject2 = alg.toJwtObjectWithVerifyOrNull(jwt, jwtKey)
        println(jwtObject2)

        Assertions.assertEquals(jwtObject2!!.header("h1"), "v1")
        Assertions.assertEquals(jwtObject2.header("h2"), "v2")
        Assertions.assertEquals(jwtObject2.header("h3"), "v3")

        Assertions.assertEquals(jwtObject2.kid(), "kid1")

        Assertions.assertEquals(jwtObject2.audience(), "aud1")
        Assertions.assertEquals(jwtObject2.id(), "id2")
        Assertions.assertEquals(jwtObject2.issuer(), "iss3")
        Assertions.assertEquals(jwtObject2.subject(), "sub4")

        Assertions.assertEquals(jwtObject2.issuedAt(), simpleDateFormat.parse("1988-01-01 03:01:32"))
        Assertions.assertEquals(jwtObject2.notBefore(), simpleDateFormat.parse("2000-03-11 03:22:11"))
        Assertions.assertEquals(jwtObject2.expire(), simpleDateFormat.parse("2999-12-31 00:00:00"))

        Assertions.assertEquals(jwtObject2.claim("c1"), "v1")
        Assertions.assertEquals(jwtObject2.claim("c2"), "v2")
        Assertions.assertEquals(jwtObject2.claim("c3"), "v3")
    }
}