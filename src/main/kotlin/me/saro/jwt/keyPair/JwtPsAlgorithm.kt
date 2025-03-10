package me.saro.jwt.keyPair

import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.PSSParameterSpec
import java.security.spec.X509EncodedKeySpec

open class JwtPsAlgorithm(
    algorithmFullNameCopy: String
): JwtKeyPairAlgorithm<JwtPsKey> {
    override val algorithmName: String = "PS"
    override val keyAlgorithmName = "RSA"
    override val algorithmFullName: String = algorithmFullNameCopy
    private val pssParameterSpec: PSSParameterSpec = getPSSParameterSpec(algorithmFullNameCopy)

    override fun getKeyPairSignature(): Signature {
        val keyPairSignature = Signature.getInstance("RSASSA-PSS")
        keyPairSignature.setParameter(pssParameterSpec)
        return keyPairSignature
    }

    override fun toJwtKey(keyPair: KeyPair): JwtPsKey =
        JwtPsKey(this, keyPair)

    override fun newRandomJwtKey(): JwtKey =
        newRandomJwtKey(2048)

    // 2048, 3072, 4096
    fun newRandomJwtKey(bit: Int): JwtPsKey =
        KeyPairGenerator.getInstance(keyAlgorithmName).let {
            it.initialize(bit)
            JwtPsKey(this, it.genKeyPair())
        }

    override fun toJwtKey(publicKey: String, privateKey: String): JwtPsKey =
        getKeyFactory().run {
            toJwtKey(
                KeyPair(
                    generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(publicKey)))),
                    generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(JwtUtils.normalizePem(privateKey))))
                )
            )
        }

    companion object {
        fun getPSSParameterSpec(algorithmFullName: String): PSSParameterSpec = when (algorithmFullName) {
            "PS256" -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
            "PS384" -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
            "PS512" -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
