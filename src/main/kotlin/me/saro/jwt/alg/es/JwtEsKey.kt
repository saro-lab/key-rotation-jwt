package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtEsAlgorithm
import me.saro.jwt.core.JwtKey
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class JwtEsKey(
    override val algorithm: JwtEsAlgorithm,
    val keyPair: KeyPair,
): JwtKey(algorithm) {
    override val stringify: String get() = "${algorithm.fullname} $publicKeyString $privateKeyString"
    override fun signature(body: ByteArray): ByteArray {

    }

    override fun signature(body: ByteBuffer): ByteArray {
        TODO("Not yet implemented")
    }

    override fun verifySignature(body: ByteArray, signature: ByteArray): Boolean {
        TODO("Not yet implemented")
    }

    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun toString(): String = stringify
}
