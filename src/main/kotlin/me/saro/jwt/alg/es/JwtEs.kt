package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*

abstract class JwtEs: JwtAlgorithm{
    companion object {
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
        private val DE_BASE64 = Base64.getDecoder()
        private const val KEY_ALGORITHM = "EC"
    }

    abstract fun getECGenParameterSpec(): ECGenParameterSpec
    abstract fun getSignature(): Signature

    override fun signature(key: JwtKey, body: String): String {
        val signature = getSignature()
        signature.initSign((key as JwtEsKey).keyPair.private)
        signature.update(body.toByteArray())
        return EN_BASE64_URL_WOP.encodeToString(signature.sign())
    }

    override fun randomJwtKey(): JwtKey =
        JwtEsKey(
            KeyPairGenerator.getInstance(KEY_ALGORITHM)
                .apply { initialize(getECGenParameterSpec()) }
                .genKeyPair()
        )

    override fun verify(key: JwtKey, jwt: String, jwtObject: JwtObject): JwtObject {
        val signature = getSignature()
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            signature.initVerify((key as JwtEsKey).keyPair.public)
            signature.update(jwt.substring(0, lastPoint).toByteArray())
            if (signature.verify(DE_BASE64_URL.decode(jwt.substring(lastPoint + 1)))) {
                if (jwtObject.header("alg") != algorithm()) {
                    throw JwtException("algorithm does not matched jwt : $jwt")
                }
                return jwtObject
            }
        }
        throw JwtException("invalid jwt : $jwt")
    }

    override fun parseJwtKey(text: String): JwtKey {
        val keyFactory = KeyFactory.getInstance(KEY_ALGORITHM)
        val textKeyPair = text.split(' ')
        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(DE_BASE64.decode(textKeyPair[0])))
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(DE_BASE64.decode(textKeyPair[1])))
        return JwtEsKey(KeyPair(publicKey, privateKey))
    }
}