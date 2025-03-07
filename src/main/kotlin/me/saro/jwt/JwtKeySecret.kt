package me.saro.jwt

import javax.crypto.spec.SecretKeySpec

interface JwtKeySecret: JwtKey {
    val secret: SecretKeySpec
    val secretBase64Url: String get() = JwtUtils.encodeBase64UrlString(secret.encoded)
}
