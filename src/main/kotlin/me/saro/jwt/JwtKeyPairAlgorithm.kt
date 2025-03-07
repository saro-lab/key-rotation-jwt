package me.saro.jwt

import java.security.*

interface JwtKeyPairAlgorithm<T: JwtKey> : JwtAlgorithm {

    val keyAlgorithmName: String

    fun getKeyFactory(): KeyFactory =
        KeyFactory.getInstance(keyAlgorithmName)

    fun getKeyPairSignature(): Signature

    fun toJwtKey(keyPair: KeyPair): T

    fun toJwtKey(publicKey: PublicKey, privateKey: PrivateKey): T =
        toJwtKey(KeyPair(publicKey, privateKey))

    fun toJwtKey(publicKey: String, privateKey: String): T
}
