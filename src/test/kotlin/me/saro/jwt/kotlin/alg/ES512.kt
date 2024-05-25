package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.es.JwtEs512
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtClaims.Companion.create
import me.saro.jwt.core.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] ES512")
class ES512 {

    fun alg(): JwtAlgorithm {
        return JwtEs512()
    }

    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val jwt = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk"
        val publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZPDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwMAl8G7CqwoJOsW7Kddns="
        val privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew=="

        val alg = alg()
        val key = alg.toJwtKey("$publicKey $privateKey")

        println("example")
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(jwt, key) }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtClaims(jwt, alg.newRandomJwtKey()) }
        println("example jwt error text - pass")
    }

    @Test
    @DisplayName("kid test")
    fun t2() {
        val alg = alg()
        val keys = HashMap<String?, JwtKey>()
        val jwtList = ArrayList<String>()
        for (i in 0..29) {
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey()
            keys[kid] = key
            val jc = create()
            jc.id("abc")
            jc.expire(OffsetDateTime.now().plusMinutes(30))
            jwtList.add(Assertions.assertDoesNotThrow<String> {
                alg.toJwt(
                    key,
                    jc,
                    kid
                )
            })
        }
        jwtList.parallelStream().forEach { jwt: String? ->
            val jh = alg.toJwtHeader(jwt)
            val key = keys[jh.kid]
            Assertions.assertNotNull(key)
            val jc = Assertions.assertDoesNotThrow<JwtClaims> {
                alg.toJwtClaims(
                    jwt!!,
                    key
                )
            }
            Assertions.assertThrows(
                JwtException::class.java
            ) { alg.toJwtClaims(jwt!!, alg.newRandomJwtKey()) }
            Assertions.assertEquals(jc.id, "abc")
        }
        println("done")
    }

    @Test
    @DisplayName("expire test")
    fun t3() {
        val alg = alg()
        val key = alg.newRandomJwtKey()
        val jcp = create()
        jcp.expire(OffsetDateTime.now().plusMinutes(30))
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(alg.toJwt(key, jcp), key) }
        val jce = create()
        jce.expire(OffsetDateTime.now().minusMinutes(30))
        Assertions.assertThrowsExactly(
            JwtException::class.java,
            { alg.toJwtClaims(alg.toJwt(key, jce), key) }, JwtExceptionCode.DATE_EXPIRED.name
        )
    }

    @Test
    @DisplayName("not before test")
    fun t4() {
        val alg = alg()
        val key = alg.newRandomJwtKey()
        val jcp = create()
        jcp.notBefore(OffsetDateTime.now().minusMinutes(30))
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(alg.toJwt(key, jcp), key) }
        val jce = create()
        jce.notBefore(OffsetDateTime.now().plusMinutes(30))
        Assertions.assertThrowsExactly(
            JwtException::class.java,
            { alg.toJwtClaims(alg.toJwt(key, jce), key) }, JwtExceptionCode.DATE_EXPIRED.name
        )
    }

    @Test
    @DisplayName("data test")
    fun t5() {
        val alg = alg()
        val key = alg.newRandomJwtKey()
        val jc = create()
        jc.issuedAt(OffsetDateTime.now())
        jc.notBefore(OffsetDateTime.now().minusMinutes(1))
        jc.expire(OffsetDateTime.now().plusMinutes(30))
        jc.id("jti value")
        jc.issuer("iss value")
        jc.subject("sub value")
        jc.audience("aud value")
        jc.claim("custom", "custom value")
        println(jc)
        val jwt = alg.toJwt(key, jc)
        println(jwt)
        val njc = Assertions.assertDoesNotThrow<JwtClaims> {
            alg.toJwtClaims(
                jwt,
                key
            )
        }
        println(njc)
        Assertions.assertEquals(njc.id, "jti value")
        Assertions.assertEquals(njc.issuer, "iss value")
        Assertions.assertEquals(njc.subject, "sub value")
        Assertions.assertEquals(njc.audience, "aud value")
        Assertions.assertEquals(njc.claim("custom"), "custom value")
    }
}