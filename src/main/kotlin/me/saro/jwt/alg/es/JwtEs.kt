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

    abstract fun getECGenParameterSpec(): ECGenParameterSpec

    fun newRandomJwtKey(): JwtKey =
        JwtEsKey(
            KeyPairGenerator.getInstance(KEY_ALGORITHM)
                .apply { initialize(getECGenParameterSpec()) }
                .genKeyPair()
        )

    override fun toJwtKey(publicKey: String, privateKey: String): JwtKey =
        KeyFactory.getInstance(KEY_ALGORITHM).run {
            JwtEsKey(KeyPair(generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(publicKey))), generatePrivate(PKCS8EncodedKeySpec(
                JwtUtils.decodeBase64(privateKey)))))
        }
}