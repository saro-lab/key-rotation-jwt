package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] HS256")
class HS256 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        val exJwtSign = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        val secret = "your-256-bit-secret"

        val alg = JwtHs256()
        val key = alg.getJwtKey(secret)

        val newJwtSign = alg.signature(exJwtBody, key)

        Assertions.assertEquals(exJwtSign, newJwtSign)

        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign + "1", key) }
        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign + "1", key) }
    }
}