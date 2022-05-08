package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: JwtAlgorithm {
    companion object {
        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
        private val MOLD_LEN = MOLD.size
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
    }

    abstract fun getKeyAlgorithm(): String
    abstract fun getMac(): Mac

    @Throws(JwtException::class)
    override fun toJwtKey(key: String): JwtKey = try {
        val point = key.indexOf(':')
        JwtHsKey(SecretKeySpec((key.substring(point + 1)).toByteArray(Charsets.UTF_8), key.substring(0, point)))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun newRandomJwtKey(): JwtKey =
        getJwtKey(32, 64)

    fun getJwtKey(secret: String): JwtKey =
        JwtHsKey(SecretKeySpec(secret.toByteArray(), getKeyAlgorithm()))

    fun getJwtKey(minLength: Int, maxLength: Int): JwtKey {
        if (minLength > maxLength) {
            throw IllegalArgumentException("maxLength must be greater than minLength")
        }
        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
        }
        return getJwtKey(chars.toString())
    }

    @Throws(JwtException::class)
    override fun signature(body: String, jwtKey: JwtKey): String = try {
        val mac = getMac().apply { init((jwtKey as JwtHsKey).key) }
        EN_BASE64_URL_WOP.encodeToString(mac.doFinal(body.toByteArray()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }
}
