package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class JwtEsKey(
    val keyPair: KeyPair
): JwtKey {
    override fun toString(): String = "JwtEsKey($publicKeyString,$privateKeyString)"
    override val algorithm: String get() = "ES"
    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
}
