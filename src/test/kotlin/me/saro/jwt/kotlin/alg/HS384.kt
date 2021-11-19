package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.es.JwtEs384
import me.saro.jwt.alg.hs.JwtHs384
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Function

@DisplayName("[Kotlin] HS384")
class HS384 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpYXQiOjE2MzcyNTk0NDEsImV4cCI6MTYzNzM0NTg0MX0"
        val exJwtSign = "OgkRovv9QLVtPTwdZgkobRNK0cbqqVi_-XELviEAceYzSDYjcHpzC9YA5GOEyKtL"
        val secret = "your-256-bit-secret"

        val alg = JwtHs384()
        val key = alg.getJwtKey(secret)

        val newJwtSign = alg.signature(exJwtBody, key)

        Assertions.assertEquals(exJwtSign, newJwtSign)

        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })

        Assertions.assertThrows(JwtException::class.java) {
            alg.toJwtObjectWithVerify(
                exJwtBody + "." + exJwtSign + "1",
                key
            )
        }
        Assertions.assertThrows(JwtException::class.java) {
            alg.toJwtObjectWithVerify(
                exJwtBody + "." + newJwtSign + "1",
                key
            )
        }
    }
}