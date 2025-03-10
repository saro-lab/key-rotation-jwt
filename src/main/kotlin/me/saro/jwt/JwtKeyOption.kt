package me.saro.jwt

import java.util.*

class JwtKeyOption private constructor(
    var kid: String,
    var notBefore: Long,
    var expire: Long,
) {
    constructor(): this(UUID.randomUUID().toString(), 0, 0)
}
