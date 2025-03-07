package me.saro.jwt

import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

interface JwtKeyPairAlgorithm<T: JwtKey> : JwtAlgorithm {

    val keyAlgorithmName: String

    fun getKeyFactory(): KeyFactory =
        KeyFactory.getInstance(keyAlgorithmName)

    fun getKeyPairSignature(): Signature

    fun toJwtKey(keyPair: KeyPair): T

    fun toJwtKey(publicKey: PublicKey, privateKey: PrivateKey): T =
        toJwtKey(KeyPair(publicKey, privateKey))

    fun toJwtKey(publicKey: String, privateKey: String): T =
        getKeyFactory().run {
            toJwtKey(
                KeyPair(
                    generatePublic(X509EncodedKeySpec(JwtUtils.decodeBase64(publicKey))),
                    generatePrivate(PKCS8EncodedKeySpec(JwtUtils.decodeBase64(privateKey)))
                )
            )
        }
}
