package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.Signature

interface JwtAlgorithmKeyPair : JwtAlgorithm {
    @Throws(JwtException::class)
    fun toJwtKey(publicKey: String, privateKey: String): JwtKey

    override fun toJwtKeyByStringify(stringify: String): JwtKey = stringify.let {
        val iof = it.indexOf(' ')
        if (iof == -1) throw JwtException(JwtExceptionCode.INVALID_KEY, "invalid jwt key format")
        toJwtKey(it.substring(0, iof), it.substring(iof + 1))
    }

    fun getSignature(): Signature

    override fun signature(body: String, jwtKey: JwtKey): String {
        val signature = getSignature()
        signature.initSign(jwtKey.private)
        signature.update(body.toByteArray())
        return JwtUtils.encodeToBase64UrlWopString(signature.sign())
    }

    @Throws(JwtException::class)
    override fun toJwtClaims(jwt: String, jwtKey: JwtKey?): JwtClaims {
        jwtKey ?: throw JwtException(JwtExceptionCode.INVALID_KEY)
        toJwtHeader(jwt).assertAlgorithm(algorithm())
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            val signature = getSignature()
            signature.initVerify(jwtKey.public)
            signature.update(jwt.substring(0, lastPoint).toByteArray())
            val verify = try {
                signature.verify(JwtUtils.decodeBase64Url(jwt.substring(lastPoint + 1)))
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
            if (verify) {
                return Jwt.toJwtClaimsWithoutVerify(jwt).apply { assert() }
            } else {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
        } else {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}
