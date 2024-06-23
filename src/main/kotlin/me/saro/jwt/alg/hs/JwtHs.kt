package me.saro.jwt.alg.hs

import me.saro.jwt.core.*
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: JwtAlgorithmHash {
    abstract fun getKeyAlgorithm(): String
    abstract fun getMac(): Mac

    @Throws(JwtException::class)
    override fun signature(body: String, jwtKey: JwtKey): String = try {
        val mac = getMac().apply { init(jwtKey.secret) }
        JwtUtils.encodeToBase64UrlWopString(mac.doFinal(body.toByteArray()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    @Throws(JwtException::class)
    override fun toJwtKey(secret: String): JwtKey = try {
       JwtHsKey(SecretKeySpec(secret.toByteArray(), getKeyAlgorithm()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }
}
