package me.saro.jwt.kotlin.es

import me.saro.jwt.alg.es.JwtEs512
import me.saro.jwt.alg.hs.JwtHs512
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Function

@DisplayName("[Kotlin] ES512")
class ES512 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody =
            "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        val exJwtSign =
            "AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk"
        val publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ" +
                "PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47" +
                "6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM" +
                "Al8G7CqwoJOsW7Kddns="
        val privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga" +
                "9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf" +
                "Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN" +
                "v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear" +
                "jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12" +
                "ew=="
        val alg = JwtEs512()
        val key = alg.parseJwtKey("$publicKey $privateKey")
        val newJwtSign = alg.signature(exJwtBody, key)
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })
        Assertions.assertThrows(Exception::class.java) {
            alg.toJwtObjectWithVerify(
                exJwtBody + "." + exJwtSign + "1",
                key
            )
        }
        Assertions.assertThrows(Exception::class.java) {
            alg.toJwtObjectWithVerify(
                exJwtBody + "." + newJwtSign + "1",
                key
            )
        }
    }

    @Test
    @DisplayName("normal")
    fun t2() {
        val alg = JwtEs512()
        val key1 = alg.randomJwtKey()
        val key2 = alg.randomJwtKey()
        val key3 = alg.parseJwtKey(key1.stringify())
        println("key1: $key1")
        println("key2: $key2")
        println("key3: $key3")
        val jwtObject = alg.createJwtObject()
        jwtObject.audience("test aud")
        jwtObject.id("id test")
        println("jwtObject: $jwtObject")
        val jwt1 = alg.toJwt(jwtObject, key1)
        val jwt2 = alg.toJwt(jwtObject, key2)
        val jwt3 = alg.toJwt(jwtObject, key3)
        println("jwt key1: $jwt1")
        println("jwt key2: $jwt2")
        println("jwt key3: $jwt3")
        Assertions.assertNotEquals(jwt1, jwt2)
        Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify(jwt1, key1) }
        Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify(jwt2, key2) }
        Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify(jwt3, key3) }
        Assertions.assertThrows(JwtException::class.java) { alg.toJwtObjectWithVerify(jwt2, key1) }
    }

    @Test
    @DisplayName("key store")
    fun t3() {
        val alg = JwtEs512()
        val keyStore = ConcurrentHashMap<String, JwtKey>()
        val jwtList = ArrayList<String>()
        for (i in 0..9) {
            val kid = Integer.toString(i)
            val key = alg.randomJwtKey()
            keyStore[kid] = key
            println("create jwt key : kid[$kid] : $key")
            val jwtObject = alg.createJwtObject()
            jwtObject.kid(kid)
            jwtObject.id("test id")
            println(jwtObject)
            val jwt = alg.toJwt(jwtObject, key)
            println(jwt)
            jwtList.add(jwt)
        }
        for (i in jwtList.indices) {
            val jwtObject =
                alg.toJwtObjectWithVerifyOrNull(jwtList[i], Function { kid: Any? -> keyStore[kid] })
            Assertions.assertNotNull(jwtObject)
            println("pass: $jwtObject")
        }
        val wrongKeyStore = ConcurrentHashMap<String, JwtKey>()
        wrongKeyStore["1"] = JwtHs512().randomJwtKey()
        for (i in jwtList.indices) {
            val jwtObject =
                alg.toJwtObjectWithVerifyOrNull(jwtList[i], Function { kid: Any? -> wrongKeyStore[kid] })
            Assertions.assertNull(jwtObject)
            println("wrong: " + jwtList[i])
        }
    }

    @Test
    @DisplayName("expire")
    fun t4() {
        val alg = JwtEs512()
        val key = alg.randomJwtKey()
        println(key)
        val validJwtObject = alg.createJwtObject()
        validJwtObject.expire(OffsetDateTime.now().plusDays(1))
        println(validJwtObject)
        val validJwt = alg.toJwt(validJwtObject, key)
        println(validJwt)
        Assertions.assertTrue(alg.verify(validJwt, key))
        val expireJwtObject = alg.createJwtObject()
        expireJwtObject.expire(OffsetDateTime.now().minusDays(1))
        println(expireJwtObject)
        val expireJwt = alg.toJwt(expireJwtObject, key)
        println(expireJwt)
        Assertions.assertFalse(alg.verify(expireJwt, key))
    }
}