package me.saro.jwt.impl

import me.saro.jwt.JwtKeyPairAlgorithm
import me.saro.jwt.JwtUtils
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

open class JwtRsAlgorithm(
    algorithmFullNameCopy: String
): JwtKeyPairAlgorithm<JwtRsKey> {
    override val algorithmName: String = "RS"
    override val keyAlgorithmName = "RSA"
    override val algorithmFullName: String = algorithmFullNameCopy
    private val signatureAlgorithm: String = getSignatureAlgorithm(algorithmFullNameCopy)

    override fun getKeyPairSignature(): Signature =
        Signature.getInstance(signatureAlgorithm)

    override fun toJwtKey(keyPair: KeyPair): JwtRsKey =
        JwtRsKey(algorithmFullName, keyPair)

    override fun newRandomJwtKey(): JwtRsKey =
        newRandomJwtKey(2048)

    // 2048, 3072, 4096
    fun newRandomJwtKey(bit: Int): JwtRsKey =
        KeyPairGenerator.getInstance(keyAlgorithmName).run {
            initialize(bit)
            JwtRsKey(algorithmFullName, genKeyPair())
        }

    override fun toJwtKey(publicKey: String, privateKey: String): JwtRsKey =
        getKeyFactory().run {
            toJwtKey(
                KeyPair(
                    generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(publicKey)))),
                    generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(privateKey))))
                )
            )
        }

    companion object {
        fun getSignatureAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "RS256" -> "SHA256withRSA"
            "RS384" -> "SHA384withRSA"
            "RS512" -> "SHA512withRSA"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
