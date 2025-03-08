package me.saro.jwt.impl

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtKeySecret
import me.saro.jwt.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import javax.crypto.spec.SecretKeySpec

class JwtHsKey(
    algorithmFullNameCopy: String,
    override val secret: SecretKeySpec
): JwtHsAlgorithm(algorithmFullNameCopy), JwtKeySecret {
    override val stringify: String = "$algorithmFullNameCopy $secretBase64"
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
