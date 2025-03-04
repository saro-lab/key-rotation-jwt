package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtAlgorithmHash
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: JwtAlgorithmHash {
    abstract fun getKeyAlgorithm(): String
    abstract fun getMac(): Mac

    override fun signature(body: ByteArray, jwtKey: JwtKey): ByteArray = try {
        val mac = getMac().apply { init(jwtKey.secret) }
        JwtUtils.encodeToBase64UrlWop(mac.doFinal(body))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun signature(body: ByteBuffer, jwtKey: JwtKey): ByteArray = try {
        val mac = getMac()
        mac.init(jwtKey.secret)
        mac.update(body)
        JwtUtils.encodeToBase64UrlWop(mac.doFinal())
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun toJwtKey(stringify: String): JwtKey = try {
       JwtHsKey(SecretKeySpec(stringify.toByteArray(), getKeyAlgorithm()))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }
}
