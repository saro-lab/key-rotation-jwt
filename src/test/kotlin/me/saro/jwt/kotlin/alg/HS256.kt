package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] HS256")
class HS256 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val alg = JwtHs256()

        val jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        val secret = "your-256-bit-secret"
        val key = alg.getJwtKey(secret)

        println("example")
        Assertions.assertDoesNotThrow<JwtClaims> { alg.toJwtClaims(jwt, key) }
        println("example jwt toJwt - pass")

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtClaims(jwt, alg.getJwtKey("is not key")) }
        println("example jwt error text - pass")
    }
}