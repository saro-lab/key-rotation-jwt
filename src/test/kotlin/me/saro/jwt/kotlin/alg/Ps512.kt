package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.ps.JwtPs512
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

@DisplayName("[Kotlin] PS512")
class Ps512 {
    var alg: JwtPs512 = Jwt.PS512

    fun randomKeyBit(): Int {
        return listOf(2048, 3072, 4096)[(Math.random() * 3).toInt()]
    }

    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val jwt =
            "eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.J5W09-rNx0pt5_HBiydR-vOluS6oD-RpYNa8PVWwMcBDQSXiw6-EPW8iSsalXPspGj3ouQjAnOP_4-zrlUUlvUIt2T79XyNeiKuooyIFvka3Y5NnGiOUBHWvWcWp4RcQFMBrZkHtJM23sB5D7Wxjx0-HFeNk-Y3UJgeJVhg5NaWXypLkC4y0ADrUBfGAxhvGdRdULZivfvzuVtv6AzW6NRuEE6DM9xpoWX_4here-yvLS2YPiBTZ8xbB3axdM99LhES-n52lVkiX5AWg2JJkEROZzLMpaacA_xlbUz_zbIaOaoqk8gB5oO7kI6sZej3QAdGigQy-hXiRnW_L98d4GQ"
        val publicKey = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
            4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
            +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
            kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
            0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
            cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
            mwIDAQAB
            -----END PUBLIC KEY-----
            """.trimIndent()
        val privateKey = """
            -----BEGIN PRIVATE KEY-----
            MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
            MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
            NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
            qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
            p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
            ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
            VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
            laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
            sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
            mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
            dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
            ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
            DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
            N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
            0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
            t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
            AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
            48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
            DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
            xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
            mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
            2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
            et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
            VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
            TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
            dn/RsYEONbwQSjIfMPkvxF+8HQ==
            -----END PRIVATE KEY-----
            """.trimIndent()

        val key = alg.toJwtKey(publicKey, privateKey)

        println("example")
        Assertions.assertDoesNotThrow<JwtNode> { parse(jwt) { node: JwtNode? -> alg.with(key) } }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(
            JwtException::class.java
        ) { parse(jwt) { node: JwtNode? -> alg.with(alg.newRandomJwtKey(randomKeyBit())) } }
        println("example jwt error text - pass")
    }

    @Test
    @DisplayName("kid test")
    fun t2() {
        val keys = HashMap<String?, JwtKey>()
        val jwtList = ArrayList<String>()

        for (i in 0..29) {
            val kid = UUID.randomUUID().toString()
            val key = alg.newRandomJwtKey(randomKeyBit())
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
            ) { parse(jwt) { node: JwtNode? -> alg.with(alg.newRandomJwtKey(randomKeyBit())) } }
            println(jwt)
            val jwtNode = Assertions.assertDoesNotThrow<JwtNode> {
                parse(jwt) { node: JwtNode ->
                    val kid = node.kid
                    println(kid)
                    println(keys[kid])
                    alg.with(keys[node.kid]!!)
                }
            }
            Assertions.assertEquals("abc", jwtNode.id)
        }
        println("done")
    }

    @Test
    @DisplayName("expire test")
    fun t3() {
        val key = alg.newRandomJwtKey(randomKeyBit())

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
        val key = alg.newRandomJwtKey(randomKeyBit())

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
        val key = alg.newRandomJwtKey(randomKeyBit())

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
