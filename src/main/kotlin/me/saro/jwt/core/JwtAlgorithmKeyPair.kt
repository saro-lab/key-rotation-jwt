package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.Signature

interface JwtAlgorithmKeyPair : JwtAlgorithm {
    companion object {
        private val DOT = ".".toByteArray()
    }

    fun toJwtKey(publicKey: String, privateKey: String): JwtKey

    override fun toJwtKey(stringify: String): JwtKey = stringify.let {
        val iof = it.indexOf(' ')
        if (iof == -1) throw JwtException(JwtExceptionCode.INVALID_KEY, "invalid jwt key format")
        toJwtKey(it.substring(0, iof), it.substring(iof + 1))
    }

    fun getSignature(): Signature

    override fun verifySignature(jwtToken: List<String>, jwtKey: JwtKey): Boolean =
        try {
            val signature = getSignature()
            signature.initVerify(jwtKey.public)
            signature.update(jwtToken[0].toByteArray())
            signature.update(DOT)
            signature.update(jwtToken[1].toByteArray())
            jwtToken[2].isNotBlank() && signature.verify(JwtUtils.decodeBase64Url(jwtToken[2]))
        } catch (_: Exception) {
            false
        }

    override fun signature(payload: String, jwtKey: JwtKey): String {
        val signature = getSignature()
        signature.initSign(jwtKey.private)
        signature.update(payload.toByteArray())
        return JwtUtils.encodeToBase64UrlWopString(signature.sign())
    }
}
