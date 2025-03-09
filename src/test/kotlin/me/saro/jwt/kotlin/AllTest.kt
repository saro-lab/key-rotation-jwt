package me.saro.jwt.kotlin

import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.parseJwt
import me.saro.jwt.Jwt.Companion.parseKey
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtNode
import me.saro.jwt.JwtUtils.Companion.encodeBase64UrlString
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import org.junit.jupiter.api.*
import java.time.OffsetDateTime
import java.util.*

@DisplayName("[Kotlin] all test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName::class)
class AllTest {
    private var createKeyMap: MutableMap<String, JwtKey> = HashMap()
    private var stringKeyMap: MutableMap<String, String> = HashMap()
    private var convertKeyMap: MutableMap<String?, JwtKey> = HashMap()

    @Test
    @DisplayName("[Kotlin] 01 created Keys")
    fun test01() {
        val start = System.currentTimeMillis()

        // HS Algorithm
        createKeyMap["HS256_1"] = Jwt.HS256.newRandomJwtKey()
        createKeyMap["HS256_2"] = Jwt.HS256.newRandomJwtKey(20)
        createKeyMap["HS256_3"] = Jwt.HS256.newRandomJwtKey(10, 40)
        createKeyMap["HS256_4"] = Jwt.HS256.toJwtKey("HS256_4_key")
        createKeyMap["HS256_5"] = Jwt.HS256.toJwtKeyByBase64Url(encodeBase64UrlString("HS256_4_key"))
        createKeyMap["HS384_1"] = Jwt.HS384.newRandomJwtKey()
        createKeyMap["HS384_2"] = Jwt.HS384.newRandomJwtKey(20)
        createKeyMap["HS384_3"] = Jwt.HS384.newRandomJwtKey(10, 40)
        createKeyMap["HS384_4"] = Jwt.HS384.toJwtKey("HS384_4_key")
        createKeyMap["HS384_5"] = Jwt.HS384.toJwtKeyByBase64Url(encodeBase64UrlString("HS384_4_key"))
        createKeyMap["HS512_1"] = Jwt.HS512.newRandomJwtKey()
        createKeyMap["HS512_2"] = Jwt.HS512.newRandomJwtKey(20)
        createKeyMap["HS512_3"] = Jwt.HS512.newRandomJwtKey(10, 40)
        createKeyMap["HS512_4"] = Jwt.HS512.toJwtKey("HS512_4_key")
        createKeyMap["HS512_5"] = Jwt.HS512.toJwtKeyByBase64Url(encodeBase64UrlString("HS512_4_key"))

        // ES Algorithm
        createKeyMap["ES256_1"] = Jwt.ES256.newRandomJwtKey()
        createKeyMap["ES256_2"] = Jwt.ES256.newRandomJwtKey()
        createKeyMap["ES256_3"] = Jwt.ES256.newRandomJwtKey()
        createKeyMap["ES384_1"] = Jwt.ES384.newRandomJwtKey()
        createKeyMap["ES384_2"] = Jwt.ES384.newRandomJwtKey()
        createKeyMap["ES384_3"] = Jwt.ES384.newRandomJwtKey()
        createKeyMap["ES512_1"] = Jwt.ES512.newRandomJwtKey()
        createKeyMap["ES512_2"] = Jwt.ES512.newRandomJwtKey()
        createKeyMap["ES512_3"] = Jwt.ES512.newRandomJwtKey()

        // PS Algorithm
        createKeyMap["PS256_1"] = Jwt.PS256.newRandomJwtKey()
        createKeyMap["PS256_2"] = Jwt.PS256.newRandomJwtKey(2048)
        createKeyMap["PS256_3"] = Jwt.PS256.newRandomJwtKey(3072)
        createKeyMap["PS256_4"] = Jwt.PS256.newRandomJwtKey(4096)
        createKeyMap["PS384_1"] = Jwt.PS384.newRandomJwtKey()
        createKeyMap["PS384_2"] = Jwt.PS384.newRandomJwtKey(2048)
        createKeyMap["PS384_3"] = Jwt.PS384.newRandomJwtKey(3072)
        createKeyMap["PS384_4"] = Jwt.PS384.newRandomJwtKey(4096)
        createKeyMap["PS512_1"] = Jwt.PS512.newRandomJwtKey()
        createKeyMap["PS512_2"] = Jwt.PS512.newRandomJwtKey(2048)
        createKeyMap["PS512_3"] = Jwt.PS512.newRandomJwtKey(3072)
        createKeyMap["PS512_4"] = Jwt.PS512.newRandomJwtKey(4096)

        // RS Algorithm
        createKeyMap["RS256_1"] = Jwt.RS256.newRandomJwtKey()
        createKeyMap["RS256_2"] = Jwt.RS256.newRandomJwtKey(2048)
        createKeyMap["RS256_3"] = Jwt.RS256.newRandomJwtKey(3072)
        createKeyMap["RS256_4"] = Jwt.RS256.newRandomJwtKey(4096)
        createKeyMap["RS384_1"] = Jwt.RS384.newRandomJwtKey()
        createKeyMap["RS384_2"] = Jwt.RS384.newRandomJwtKey(2048)
        createKeyMap["RS384_3"] = Jwt.RS384.newRandomJwtKey(3072)
        createKeyMap["RS384_4"] = Jwt.RS384.newRandomJwtKey(4096)
        createKeyMap["RS512_1"] = Jwt.RS512.newRandomJwtKey()
        createKeyMap["RS512_2"] = Jwt.RS512.newRandomJwtKey(2048)
        createKeyMap["RS512_3"] = Jwt.RS512.newRandomJwtKey(3072)
        createKeyMap["RS512_4"] = Jwt.RS512.newRandomJwtKey(4096)

        Assertions.assertEquals(48, createKeyMap.size)
        println("create " + createKeyMap.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 02 stringify keys")
    fun test02() {
        Assertions.assertNotEquals(0, createKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        createKeyMap.forEach { (kid, key) -> stringKeyMap[kid] = key.stringify }

        Assertions.assertEquals(48, stringKeyMap.size)

        stringKeyMap.forEach { (kid, key) -> println("$kid : $key") }
        println("pass stringify " + stringKeyMap.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 03 convert string keys")
    fun test03() {
        Assertions.assertNotEquals(0, stringKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        stringKeyMap.forEach { (kid, key) -> convertKeyMap[kid] = parseKey(key) }

        Assertions.assertEquals(48, convertKeyMap.size)

        println("pass convert " + convertKeyMap.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 04 expired")
    fun test04() {
        Assertions.assertNotEquals(0, createKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        createKeyMap.forEach { (kid, key) ->
            val jwt = Jwt.createJwt(key)
                .expire(OffsetDateTime.now().minusMinutes(1))
                .toJwt()

            val exception = Assertions.assertThrows(JwtException::class.java) { parseJwt(jwt) { node: JwtNode -> convertKeyMap[node.kid] } }

            Assertions.assertEquals(JwtExceptionCode.DATE_EXPIRED, exception.code)
        }
        stringKeyMap.forEach { (kid, key) -> convertKeyMap[kid] = parseKey(key) }

        println("pass expired test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 05 not before")
    fun test05() {
        Assertions.assertNotEquals(0, createKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        createKeyMap.forEach { (kid, key) ->
            val jwt = Jwt.createJwt(key)
                .notBefore(OffsetDateTime.now().plusDays(1))
                .toJwt()

            val exception = Assertions.assertThrows(JwtException::class.java) { parseJwt(jwt) { node: JwtNode -> convertKeyMap[node.kid] } }

            Assertions.assertEquals(JwtExceptionCode.DATE_BEFORE, exception.code)
        }
        stringKeyMap.forEach { (kid, key) -> convertKeyMap[kid] = parseKey(key) }

        println("pass not before test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 06 pass")
    fun test06() {
        Assertions.assertNotEquals(0, createKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        createKeyMap.forEach { (kid, key) ->
            val jwt = Jwt.createJwt(key)
                .toJwt()

            val node = Assertions.assertDoesNotThrow<JwtNode> { parseJwt(jwt) { it: JwtNode -> convertKeyMap[it.kid] } }

            Assertions.assertEquals(kid, node.kid)
        }

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 07 data")
    fun test07() {
        Assertions.assertNotEquals(0, createKeyMap.size, "This function cannot be tested independently. Please run the entire test.")

        val start = System.currentTimeMillis()

        val issuer = "issuer1"
        val subject = "subject2"
        val audience = "audience3"
        val id = "id4"
        val boolData = true
        val boolData2 = "no"
        val boolData3 = "1"
        val boolData4 = "Y"
        val boolData5 = "YeS"
        val boolData6 = "N"
        val intData1 = 1237890
        val intData2 = "-7890"
        val longData1 = 1234567891110L
        val longData2 = "42345678911103"
        val issuedAt = Date(OffsetDateTime.now().toEpochSecond() * 1000L)
        val notBefore = OffsetDateTime.now().minusMinutes(1).toEpochSecond()
        val expire = OffsetDateTime.now().plusHours(1).toEpochSecond()

        createKeyMap.forEach { (kid, key) ->
            val jwt = Jwt.createJwt(key)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .claim("boolData3", boolData3)
                .claim("boolData4", boolData4)
                .claim("boolData5", boolData5)
                .claim("boolData6", boolData6)
                .claim("intData1", intData1)
                .claim("intData2", intData2)
                .claim("longData1", longData1)
                .claim("longData2", longData2)
                .claim("test", "test-value")
                .issuedAt(issuedAt)
                .notBefore(notBefore)
                .expire(expire)
                .toJwt()

            val node = Assertions.assertDoesNotThrow<JwtNode> { parseJwt(jwt) { it: JwtNode -> convertKeyMap[it.kid] } }

            Assertions.assertEquals(kid, node.kid)
            Assertions.assertEquals(key.algorithm.algorithmFullName, node.algorithm)
            Assertions.assertEquals(issuer, node.issuer)
            Assertions.assertEquals(subject, node.subject)
            Assertions.assertEquals(audience, node.audience)
            Assertions.assertEquals(id, node.id)
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"))
            Assertions.assertEquals(false, node.claimBoolean("boolData2"))
            Assertions.assertEquals(true, node.claimBoolean("boolData3"))
            Assertions.assertEquals(true, node.claimBoolean("boolData4"))
            Assertions.assertEquals(true, node.claimBoolean("boolData5"))
            Assertions.assertEquals(false, node.claimBoolean("boolData6"))
            Assertions.assertEquals(intData1, node.claimInt("intData1"))
            Assertions.assertEquals(-7890, node.claimInt("intData2"))
            Assertions.assertEquals(longData1, node.claimLong("longData1"))
            Assertions.assertEquals(42345678911103L, node.claimLong("longData2"))
            Assertions.assertEquals("test-value", node.claimString("test"))
            Assertions.assertEquals(issuedAt, node.issuedAt)
            Assertions.assertEquals(notBefore, node.notBeforeEpochSecond)
            Assertions.assertEquals(expire, node.expireEpochSecond)
            println("pass: $node")
        }

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }
}
