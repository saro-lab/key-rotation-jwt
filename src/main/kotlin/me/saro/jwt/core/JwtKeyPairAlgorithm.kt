package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.nio.ByteBuffer
import java.security.Signature

interface JwtKeyPairAlgorithm : JwtAlgorithm {
    fun toJwtKey(publicKey: String, privateKey: String): JwtKey

    override fun toJwtKey(stringify: String): JwtKey = stringify.let {
        val iof = it.indexOf(' ')
        if (iof == -1) throw JwtException(JwtExceptionCode.INVALID_KEY, "invalid jwt key format")
        toJwtKey(it.substring(0, iof), it.substring(iof + 1))
    }

    fun getSignature(): Signature

    override fun verifySignature(body: ByteArray, signature: ByteArray, jwtKey: JwtKey): Boolean = try {
        val sig = getSignature()
        sig.initVerify(jwtKey.public)
        sig.update(body)
        sig.verify(JwtUtils.decodeBase64Url(signature))
    } catch (_: Exception) {
        false
    }

    override fun signature(body: ByteArray, jwtKey: JwtKey): ByteArray {
        val signature = getSignature()
        signature.initSign(jwtKey.private)
        signature.update(body)
        return JwtUtils.encodeToBase64UrlWop(signature.sign())
    }

    override fun signature(body: ByteBuffer, jwtKey: JwtKey): ByteArray {
        val signature = getSignature()
        signature.initSign(jwtKey.private)
        signature.update(body)
        return JwtUtils.encodeToBase64UrlWop(signature.sign())
    }
}
