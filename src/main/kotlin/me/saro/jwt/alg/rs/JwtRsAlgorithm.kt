package me.saro.jwt.alg.rs

import me.saro.jwt.core.JwtKeyPairAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtUtils
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

abstract class JwtRsAlgorithm: JwtKeyPairAlgorithm {
    companion object {
        private const val KEY_ALGORITHM = "RSA"
    }

    fun newRandomJwtKey(bit: Int): JwtKey =
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
}