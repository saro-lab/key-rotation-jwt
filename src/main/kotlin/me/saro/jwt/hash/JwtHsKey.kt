package me.saro.jwt.hash

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*
import javax.crypto.spec.SecretKeySpec

class JwtHsKey(
    algorithmFullNameCopy: String,
    private val secret: SecretKeySpec,
): JwtHsAlgorithm(algorithmFullNameCopy), JwtKey {
    override var kid: String = UUID.randomUUID().toString()
    override var notBefore: Long = 0
    override var expire: Long = 0
    override val stringify: String get() = JwtUtils.writeValueAsString(mapOf(
        "algorithm" to algorithm.algorithmFullName,
        "kid" to kid,
        "notBefore" to notBefore,
        "expire" to expire,
        "secret" to secretBase64,
    ))
    private val secretBase64: String get() = JwtUtils.encodeBase64String(secret.encoded)
    override val algorithm: JwtAlgorithm = this

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    override fun signature(body: ByteArray): ByteArray = try {
        val mac = getMac().apply { init(secret) }
        JwtUtils.encodeToBase64UrlWop(mac.doFinal(body))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun verifySignature(body: ByteArray, signature: ByteArray): Boolean = try {
        signature.contentEquals(signature(body))
    } catch (_: Exception) {
        false
    }
}
