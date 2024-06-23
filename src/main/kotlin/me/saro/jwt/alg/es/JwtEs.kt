package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class JwtEs: JwtAlgorithm{
    companion object {
        private const val KEY_ALGORITHM = "EC"
    }

    abstract fun getECGenParameterSpec(): ECGenParameterSpec
    abstract fun getSignature(): Signature

    override fun signature(body: String, jwtKey: JwtKey): String {
        val signature = getSignature()
        signature.initSign((jwtKey as JwtEsKey).keyPair.private)
        signature.update(body.toByteArray())
        return JwtUtils.encodeToBase64UrlWopString(signature.sign())
    }

    override fun newRandomJwtKey(): JwtKey =
        JwtEsKey(
            KeyPairGenerator.getInstance(KEY_ALGORITHM)
                .apply { initialize(getECGenParameterSpec()) }
                .genKeyPair()
        )

    override fun toJwtKey(key: String): JwtKey {
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        val textKeyPair = key.split(' ')
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(textKeyPair[0])))
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(textKeyPair[1])))
        return JwtEsKey(KeyPair(publicKey, privateKey))
    }

    @Throws(JwtException::class)
    override fun toJwtClaims(jwt: String, jwtKey: JwtKey?): JwtClaims {
        jwtKey ?: throw JwtException(JwtExceptionCode.JWT_KEY_IS_NULL)
        toJwtHeader(jwt).assertAlgorithm(algorithm())
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            val signature = getSignature()
            signature.initVerify((jwtKey as JwtEsKey).keyPair.public)
            signature.update(jwt.substring(0, lastPoint).toByteArray())
            if (signature.verify(JwtUtils.decodeBase64Url(jwt.substring(lastPoint + 1)))) {
                return JwtUtils.toJwtClaimsWithoutVerify(jwt).apply { assert() }
            } else {
                throw JwtException(JwtExceptionCode.INVALID_SIGNATURE)
            }
        } else {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}