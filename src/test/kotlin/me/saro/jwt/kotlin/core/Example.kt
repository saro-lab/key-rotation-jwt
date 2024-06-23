package me.saro.jwt.kotlin.core

import me.saro.jwt.core.Jwt
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtClaims.Companion.create
import me.saro.jwt.core.JwtKey
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Java] example")
class Example {
    fun alg(): JwtAlgorithm = Jwt.es256()

    @Test
    @DisplayName("basic")
    fun t1() {

        val alg = alg()
        val key = alg.newRandomJwtKey()
        val claims = create()

        claims.issuedAt(OffsetDateTime.now())
        claims.notBefore(OffsetDateTime.now().minusMinutes(1))
        claims.expire(OffsetDateTime.now().plusMinutes(30))
        claims.id("jti value")
        claims.issuer("iss value")
        claims.subject("sub value")
        claims.audience("aud value")
        claims.claim("custom", "custom value")

        println(claims)

        val jwt = alg.toJwt(key, claims)

        println(jwt)

        val newClaims = Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(jwt, key) }

        println(newClaims)

        Assertions.assertEquals(newClaims.id, "jti value")
        Assertions.assertEquals(newClaims.issuer, "iss value")
        Assertions.assertEquals(newClaims.subject, "sub value")
        Assertions.assertEquals(newClaims.audience, "aud value")
        Assertions.assertEquals(newClaims.claim("custom"), "custom value")
    }

    @Test
    @DisplayName("dynamic key")
    fun t2() {
        val alg = alg()
        val keyMap = HashMap<String?, JwtKey>()
        val jwtList = ArrayList<String>()

        // make keys
        for (i in 0..29) {
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey()
            keyMap[kid] = key
            // key to string (save DB)
            // - key.stringify()
            // string to key (load DB)
            // - alg.toJwtKey(key.stringify())
        }

        // make jwt list with random key
        for (i in 0..9) {
            val claims = create()
            claims.issuedAt(OffsetDateTime.now())
            claims.notBefore(OffsetDateTime.now().minusMinutes(1))
            claims.expire(OffsetDateTime.now().plusMinutes(30))
            claims.id("jti value $i")
            claims.issuer("iss value $i")
            claims.subject("sub value $i")
            claims.audience("aud value $i")
            claims.claim("custom", "custom value $i")
            val randomKid = keyMap.keys.toTypedArray()[(Math.random() * keyMap.size).toInt()] as String
            val randomKey = keyMap[randomKid]

            // make jwt with key / kid(header)
            val jwt = alg.toJwt(randomKey!!, claims, randomKid)
            jwtList.add(jwt)
        }

        // decode
        for (i in 0..9) {
            val jwt = jwtList[i]
            val header = alg.toJwtHeader(jwt)
            val key = keyMap[header.kid]
            val claims = alg.toJwtClaims(jwt, key)

            println()
            println("jwt : $jwt")
            println(header)
            println(claims)

            Assertions.assertEquals(claims.id, "jti value $i")
            Assertions.assertEquals(claims.issuer, "iss value $i")
            Assertions.assertEquals(claims.subject, "sub value $i")
            Assertions.assertEquals(claims.audience, "aud value $i")
            Assertions.assertEquals(claims.claim("custom"), "custom value $i")
        }
    }
}