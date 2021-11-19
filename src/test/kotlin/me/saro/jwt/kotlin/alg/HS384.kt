package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.hs.JwtHs384
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] HS384")
class HS384 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        val exJwtSign = "bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh"
        val secret = "your-384-bit-secret"

        val alg = JwtHs384()
        val key = alg.getJwtKey(secret)

        val newJwtSign = alg.signature(exJwtBody, key)

        Assertions.assertEquals(exJwtSign, newJwtSign)

        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })

        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign + "1", key) }
        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign + "1", key) }
    }
}