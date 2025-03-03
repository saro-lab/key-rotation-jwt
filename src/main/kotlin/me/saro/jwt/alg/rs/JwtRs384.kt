package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs384 internal constructor(): JwtRs() {
    override val algorithm: String = "RS384"
    override fun getSignature(): Signature = Signature.getInstance("SHA384withRSA")
}