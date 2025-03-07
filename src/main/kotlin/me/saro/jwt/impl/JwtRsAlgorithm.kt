package me.saro.jwt.impl

import me.saro.jwt.JwtKeyPairAlgorithm
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature

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

    // 2048, 3072, 4096
    fun newRandomJwtKey(bit: Int): JwtRsKey =
        KeyPairGenerator.getInstance(keyAlgorithmName).run {
            initialize(bit)
            JwtRsKey(algorithmFullName, genKeyPair())
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
