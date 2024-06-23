package me.saro.jwt.alg.ps

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class JwtPsKey(
    val keyPair: KeyPair
): JwtKey {
    override val stringify: String get() = "$publicKeyString $privateKeyString"
    override val algorithm: String get() = "PS"
    override val public: PublicKey get() = keyPair.public
    override val private: PrivateKey get() = keyPair.private
    override fun toString(): String = "JwtPsKey($publicKeyString,$privateKeyString)"
}
