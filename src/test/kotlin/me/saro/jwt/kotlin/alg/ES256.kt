package me.saro.jwt.kotlin.alg

import me.saro.jwt.alg.es.JwtEs256
import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentHashMap
import java.util.function.Function

@DisplayName("[Kotlin] ES256")
class ES256 {
    @Test
    @DisplayName("check jwt.io example")
    fun t1() {
        val exJwtBody = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        val exJwtSign = "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        val publicKey = (
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9" +
                "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=="
        )
        val privateKey = (
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2" +
                "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r" +
                "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G"
        )

        val alg = JwtEs256()

        val key = alg.parseJwtKey("$publicKey $privateKey")
        val newJwtSign = alg.signature(exJwtBody, key)

        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })

        Assertions.assertThrows(Exception::class.java) {
            alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign + "1", key)
        }
        Assertions.assertThrows(Exception::class.java) {
            alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign + "1", key)
        }
    }
}