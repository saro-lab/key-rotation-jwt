package me.saro.jwt.impl

import me.saro.jwt.JwtKeyPairAlgorithm
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

open class JwtEsAlgorithm(
    algorithmFullNameCopy: String
): JwtKeyPairAlgorithm<JwtEsKey> {
    override val algorithmName: String = "ES"
    override val keyAlgorithmName = "EC"
    override val algorithmFullName: String = algorithmFullNameCopy
    private val signatureAlgorithm: String = getSignatureAlgorithm(algorithmFullNameCopy)

    override fun getKeyPairSignature(): Signature =
        Signature.getInstance(signatureAlgorithm)

    private val genParameterSpec: ECGenParameterSpec = getGenParameterSpec(algorithmFullNameCopy)

    override fun toJwtKey(keyPair: KeyPair): JwtEsKey =
        JwtEsKey(algorithmFullName, keyPair)

    fun newRandomJwtKey(): JwtEsKey =
        KeyPairGenerator.getInstance(keyAlgorithmName).run {
            initialize(genParameterSpec)
            JwtEsKey(algorithmFullName, genKeyPair())
        }

    companion object {
        fun getSignatureAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "ES256" -> "SHA256withECDSAinP1363Format"
            "ES384" -> "SHA384withECDSAinP1363Format"
            "ES512" -> "SHA512withECDSAinP1363Format"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
        fun getGenParameterSpec(algorithmFullName: String): ECGenParameterSpec = when (algorithmFullName) {
            "ES256" -> ECGenParameterSpec("secp256r1")
            "ES384" -> ECGenParameterSpec("secp384r1")
            "ES512" -> ECGenParameterSpec("secp521r1")
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
