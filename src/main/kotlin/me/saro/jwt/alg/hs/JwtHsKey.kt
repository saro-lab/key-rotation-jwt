package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtKey
import javax.crypto.spec.SecretKeySpec

data class JwtHsKey(
    override val secret: SecretKeySpec,
): JwtKey {
    override fun toString(): String = secretString
    override val algorithm: String get() = "HS"
}
