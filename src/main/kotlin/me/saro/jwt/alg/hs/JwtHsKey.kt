package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtKey
import javax.crypto.spec.SecretKeySpec

data class JwtHsKey(
    override val secret: SecretKeySpec,
): JwtKey {
    override val stringify: String get() = secretString
    override val algorithm: String get() = "HS"
    override fun toString(): String = "JwtHsKey($secretString)"
}
