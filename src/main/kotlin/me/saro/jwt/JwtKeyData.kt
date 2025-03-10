package me.saro.jwt

import java.util.*

class JwtKeyData(
    var algorithm: String = "",
    var publicKey: String = "",
    var privateKey: String = "",
    var secret: String = "",
    var kid: String = UUID.randomUUID().toString(),
    var notBefore: Long = 0,
    var expire: Long = 0,
) {
}