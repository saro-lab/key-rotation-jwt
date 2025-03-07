package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtAlgorithmKeyPair
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtUtils
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class JwtEs: JwtAlgorithmKeyPair {
    companion object {
        private const val KEY_ALGORITHM = "EC"
    }

    abstract val genParameterSpec: ECGenParameterSpec

    override val keyAlgorithm: String = "EC"

    override fun newRandomJwtKey(): JwtKey {
        val kp = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        kp.initialize(genParameterSpec)
        JwtEsKey(this, kp.genKeyPair())
    }

    override fun toJwtKey(publicKey: String, privateKey: String): JwtKey =
        KeyFactory.getInstance(KEY_ALGORITHM).run {
            JwtEsKey(KeyPair(generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(publicKey))), generatePrivate(PKCS8EncodedKeySpec(
                JwtUtils.decodeBase64(privateKey)))))
        }
}