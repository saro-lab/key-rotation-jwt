package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class JwtEsKey(
    val jwtEs: JwtEs,
    val keyPair: KeyPair,
): JwtKey(jwtEs) {
    override val stringify: String get() = "${jwtEs.algorithm} $publicKeyString $privateKeyString"
    override val keyAlgorithm: String = "ES"
    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun toString(): String = stringify
}
