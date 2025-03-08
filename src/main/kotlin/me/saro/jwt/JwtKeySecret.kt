package me.saro.jwt

import javax.crypto.spec.SecretKeySpec

interface JwtKeySecret: JwtKey {
    val secret: SecretKeySpec
    val secretBase64: String get() = JwtUtils.encodeBase64String(secret.encoded)
}
