package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: JwtAlgorithm{
    companion object {
        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
        private val MOLD_LEN = MOLD.size
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
    }

    abstract fun getKeyAlgorithm(): String

    abstract fun getMac(): Mac

    override fun signature(key: JwtKey, body: String): String {
        val mac = getMac()
            .apply { init((key as JwtHsKey).key) }
        return EN_BASE64_URL_WOP.encodeToString(mac.doFinal(body.toByteArray()))
    }

    fun getJwtKey(secret: String): JwtKey =
        JwtHsKey(SecretKeySpec(secret.toByteArray(), getKeyAlgorithm()))

    fun getJwtKey(minLength: Int, maxLength: Int): JwtKey {
        if (minLength > maxLength) {
            throw JwtException("maxLength must be greater than minLength")
        }
        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
        }
        return getJwtKey(chars.toString())
    }

    override fun randomJwtKey(): JwtKey =
        getJwtKey(32, 64)

    override fun verify(key: JwtKey, jwt: String, jwtObject: JwtObject): JwtObject {
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            if (signature(key, jwt.substring(0, lastPoint)) == jwt.substring(lastPoint + 1)) {
                if (jwtObject.header("alg") != algorithm()) {
                    throw JwtException("algorithm does not matched jwt : $jwt")
                }
                return jwtObject
            }
        }
        throw JwtException("invalid jwt : $jwt")
    }

    override fun parseJwtKey(text: String): JwtKey {
        val point = text.indexOf(':')
        return JwtHsKey(SecretKeySpec((text.substring(point + 1)).toByteArray(Charsets.UTF_8), text.substring(0, point)))
    }
}