package me.saro.jwt.alg.rs

import me.saro.jwt.core.*
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class JwtRs: JwtAlgorithmPemKeyPair{
    companion object {
        private const val KEY_ALGORITHM = "RSA"
    }

    abstract fun getSignature(): Signature

    override fun signature(body: String, jwtKey: JwtKey): String {
        val signature = getSignature()
        signature.initSign(jwtKey.private)
        signature.update(body.toByteArray())
        return JwtUtils.encodeToBase64UrlWopString(signature.sign())
    }

    override fun newRandomJwtKey(bit: Int): JwtKey =
        JwtRsKey(
            KeyPairGenerator.getInstance(KEY_ALGORITHM)
                .apply { initialize(bit) }
                .genKeyPair()
        )

    override fun toJwtKey(publicKey: String, privateKey: String): JwtKey =
        KeyFactory.getInstance(KEY_ALGORITHM).run {
            val pubKey = generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(publicKey))))
            val priKey = generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(privateKey))))
            JwtRsKey(KeyPair(pubKey, priKey))
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