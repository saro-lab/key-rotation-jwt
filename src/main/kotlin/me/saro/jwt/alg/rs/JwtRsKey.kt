package me.saro.jwt.alg.rs

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class JwtRsKey(
    val keyPair: KeyPair
): JwtKey {
    override val stringify: String get() = "$publicKeyString $privateKeyString"
    override val keyAlgorithm: String get() = "RS"
    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun toString(): String = "JwtRsKey($publicKeyString,$privateKeyString)"
}
