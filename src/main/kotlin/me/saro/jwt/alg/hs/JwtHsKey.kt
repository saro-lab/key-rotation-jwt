package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtKey
import javax.crypto.spec.SecretKeySpec

data class JwtHsKey(
    val key: SecretKeySpec
): JwtKey {
    override fun stringify(): String =
        String(key.encoded, Charsets.UTF_8)

    override fun toString(): String =
        "JwtHsKey(${stringify()})"
}
