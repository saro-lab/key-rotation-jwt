package me.saro.jwt.core

import java.security.spec.ECGenParameterSpec

class JwtEsAlgorithm(
    override val fullname: String
): JwtKeyPairAlgorithm {
    override val name: String = "ES"
    private val genParameterSpec: ECGenParameterSpec
    private val signatureAlgorithm: String

    init {
        when (fullname) {
            "ES256" -> {
                genParameterSpec = ECGenParameterSpec("secp256r1")
                signatureAlgorithm = "SHA256withECDSAinP1363Format"
            }
            "ES384" -> {
                genParameterSpec = ECGenParameterSpec("secp384r1")
                signatureAlgorithm = "SHA384withECDSAinP1363Format"
            }
            "ES512" -> {
                genParameterSpec = ECGenParameterSpec("secp521r1")
                signatureAlgorithm = "SHA512withECDSAinP1363Format"
            }
            else -> throw IllegalArgumentException("unsupported algorithm: $fullname")
        }
    }


    companion object {
        private const val KEY_ALGORITHM = "EC"
    }



//    override fun newRandomJwtKey(): JwtKey {
//        val kp = KeyPairGenerator.getInstance(KEY_ALGORITHM)
//        kp.initialize(genParameterSpec)
//        JwtEsKey(this, kp.genKeyPair())
//    }
//
//    override fun toJwtKey(publicKey: String, privateKey: String): JwtKey =
//        KeyFactory.getInstance(KEY_ALGORITHM).run {
//            JwtEsKey(KeyPair(generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(publicKey))), generatePrivate(PKCS8EncodedKeySpec(
//                JwtUtils.decodeBase64(privateKey)))))
//        }
}