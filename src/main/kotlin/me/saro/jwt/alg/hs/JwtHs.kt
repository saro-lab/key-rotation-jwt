package me.saro.jwt.alg.hs

import me.saro.jwt.core.*
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: JwtAlgorithmHash {
    companion object {
        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
        private val MOLD_LEN = MOLD.size
    }

    abstract fun getKeyAlgorithm(): String
    abstract fun getMac(): Mac

    @Throws(JwtException::class)
    override fun toJwtKey(secret: String): JwtKey = try {
       JwtHsKey(SecretKeySpec(secret.toByteArray(), getKeyAlgorithm()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun newRandomJwtKey(): JwtKey =
        newRandomJwtKey(32, 64)

    fun newRandomJwtKey(minLength: Int, maxLength: Int): JwtKey {
        if (minLength > maxLength) {
            throw IllegalArgumentException("maxLength must be greater than minLength")
        }
        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
        }
        return toJwtKey(chars.toString())
    }

    @Throws(JwtException::class)
    override fun signature(body: String, jwtKey: JwtKey): String = try {
        val mac = getMac().apply { init(jwtKey.secret) }
        JwtUtils.encodeToBase64UrlWopString(mac.doFinal(body.toByteArray()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    @Throws(JwtException::class)
    override fun toJwtClaims(jwt: String, jwtKey: JwtKey?): JwtClaims {
        jwtKey ?: throw JwtException(JwtExceptionCode.JWT_KEY_IS_NULL)
        toJwtHeader(jwt).assertAlgorithm(algorithm())
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            if (signature(jwt.substring(0, lastPoint), jwtKey) == jwt.substring(lastPoint + 1)) {
                return Jwt.toJwtClaimsWithoutVerify(jwt).apply { assert() }
            } else {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
        } else {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}
