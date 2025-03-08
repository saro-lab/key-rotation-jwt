package me.saro.jwt.kotlin

import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.parseJwt
import me.saro.jwt.JwtNode
import org.junit.jupiter.api.*
import java.time.OffsetDateTime

@DisplayName("[Java] example test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(
    MethodOrderer.DisplayName::class
)
class ExampleTest {
    @Test
    @DisplayName("[Java] 01 simple test")
    fun test01() {
        println("For an applied usage example, please refer to AllTest")

        val es256 = Jwt.ES256
        val key = es256.newRandomJwtKey()

        val issuer = "issuer1"
        val subject = "subject2"
        val audience = "audience3"
        val id = "id4"
        val boolData = true
        val boolData2 = "no"
        val expire = OffsetDateTime.now().plusHours(1).toEpochSecond()

        // create jwt
        val jwt = key.newJwtBuilder()
            .issuer(issuer)
            .subject(subject)
            .audience(audience)
            .id(id)
            .claim("boolData", boolData)
            .claim("boolData2", boolData2)
            .expire(expire)
            .toJwt()

        println("jwt: $jwt")

        // parse jwt
        val node = Assertions.assertDoesNotThrow<JwtNode> { parseJwt(jwt) { key } }
        Assertions.assertEquals(key.algorithm.algorithmFullName, node.algorithm)
        Assertions.assertEquals(issuer, node.issuer)
        Assertions.assertEquals(subject, node.subject)
        Assertions.assertEquals(audience, node.audience)
        Assertions.assertEquals(id, node.id)
        Assertions.assertEquals(boolData, node.claimBoolean("boolData"))
        Assertions.assertEquals(false, node.claimBoolean("boolData2"))
        Assertions.assertEquals(expire, node.expireEpochSecond)

        println("jwt node: $node")
    }
}
