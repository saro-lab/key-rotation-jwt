package me.saro.jwt.impl

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtKeyPair
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

class JwtEsKey(
    algorithmFullNameCopy: String,
    override val keyPair: KeyPair
): JwtEsAlgorithm(algorithmFullNameCopy), JwtKeyPair {
    override val stringify: String = "$algorithmFullNameCopy $publicKeyString $privateKeyString"
    override val algorithm: JwtAlgorithm = this

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun getKeyPairSignature(): Signature = super<JwtEsAlgorithm>.getKeyPairSignature()
}
