package me.saro.jwt.kotlin.alg

import me.saro.jwt.core.Jwt
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

@DisplayName("[Kotlin] RS256")
class Rs256 {

    fun alg() = Jwt.rs256()
    fun randomKeyBit() = listOf(2048, 3072, 4096)[(Math.random() * 3).toInt()]

    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ"
        val publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n" +
                "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n" +
                "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n" +
                "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n" +
                "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n" +
                "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n" +
                "mwIDAQAB\n" +
                "-----END PUBLIC KEY-----"
        val privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n" +
                "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
                "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
                "qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg\n" +
                "p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR\n" +
                "ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi\n" +
                "VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV\n" +
                "laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8\n" +
                "sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H\n" +
                "mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY\n" +
                "dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw\n" +
                "ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ\n" +
                "DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T\n" +
                "N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t\n" +
                "0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv\n" +
                "t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU\n" +
                "AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk\n" +
                "48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL\n" +
                "DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK\n" +
                "xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA\n" +
                "mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh\n" +
                "2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz\n" +
                "et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr\n" +
                "VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD\n" +
                "TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc\n" +
                "dn/RsYEONbwQSjIfMPkvxF+8HQ==\n" +
                "-----END PRIVATE KEY-----"

        val alg = alg()
        val key = alg.toJwtKey(publicKey, privateKey)

        println("example")
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(jwt, key) }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtClaims(jwt, alg.newRandomJwtKey(randomKeyBit())) }
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
            val key = alg.newRandomJwtKey(randomKeyBit())
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
            ) { alg.toJwtClaims(jwt!!, alg.newRandomJwtKey(randomKeyBit())) }
            Assertions.assertEquals(jc.id, "abc")
        }
        println("done")
    }

    @Test
    @DisplayName("expire test")
    fun t3() {
        val alg = alg()
        val key = alg.newRandomJwtKey(randomKeyBit())
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
        val key = alg.newRandomJwtKey(randomKeyBit())
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
        val key = alg.newRandomJwtKey(randomKeyBit())
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