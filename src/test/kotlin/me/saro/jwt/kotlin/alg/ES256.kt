package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.es.JwtEs256
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

@DisplayName("[Kotlin] ES256")
class ES256 {

    fun alg(): JwtAlgorithm {
        return JwtEs256()
    }

    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        val publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=="
        val privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G"

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
            Assertions.assertEquals(jc.id(), "abc")
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
        Assertions.assertEquals(njc.id(), "jti value")
        Assertions.assertEquals(njc.issuer(), "iss value")
        Assertions.assertEquals(njc.subject(), "sub value")
        Assertions.assertEquals(njc.audience(), "aud value")
        Assertions.assertEquals(njc.claim("custom"), "custom value")
    }
}