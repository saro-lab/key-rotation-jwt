package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs512 internal constructor(): JwtRs() {
    override val algorithm: String = "RS512"
    override fun getSignature(): Signature = Signature.getInstance("SHA512withRSA")
}