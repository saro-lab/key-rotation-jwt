package me.saro.jwt.hash

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

open class JwtHsAlgorithm(
    algorithmFullNameCopy: String
): JwtAlgorithm {
    override val algorithmName: String = "RS"
    override val algorithmFullName: String = algorithmFullNameCopy
    private val keyAlgorithm: String = getKeyAlgorithm(algorithmFullNameCopy)
    protected fun getMac(): Mac = Mac.getInstance(keyAlgorithm)

    fun toJwtKey(key: ByteArray): JwtKey = try {
        JwtHsKey(algorithmFullName, SecretKeySpec(key, keyAlgorithm))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    fun toJwtKey(key: String): JwtKey =
        toJwtKey(key.toByteArray())

    fun toJwtKeyByBase64Url(encodedBase64Key: String): JwtKey =
        toJwtKey(JwtUtils.decodeBase64(encodedBase64Key))

    override fun newRandomJwtKey(): JwtKey =
        newRandomJwtKey(32)

    fun newRandomJwtKey(minKeySize: Int, maxKeySize: Int): JwtKey {
        if (minKeySize > maxKeySize) {
            throw IllegalArgumentException("minKeySize must be less than or equal to maxKeySize")
        }
        return newRandomJwtKey(minKeySize + (Math.random() * (maxKeySize - minKeySize)).toInt())
    }

    fun newRandomJwtKey(keySize: Int): JwtKey {
        if (keySize < 1) {
            throw IllegalArgumentException("length must be greater than 0")
        }
        val bytes = ByteArray(keySize)
        SecureRandom().nextBytes(bytes)
        return toJwtKey(bytes)
    }

    companion object {
        fun getKeyAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "HS256" -> "HmacSHA256"
            "HS384" -> "HmacSHA384"
            "HS512" -> "HmacSHA512"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
