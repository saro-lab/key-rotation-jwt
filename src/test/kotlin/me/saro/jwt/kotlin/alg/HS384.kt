package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs384
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] HS384")
class HS384 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val alg = JwtHs384()

        val jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh"
        val secret = "your-384-bit-secret"
        val key = alg.getJwtKey(secret)

        println("example")
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(jwt, key) }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtClaims(jwt, alg.getJwtKey("is not key")) }
        println("example jwt error text - pass")
    }
}