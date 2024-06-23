package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs256 internal constructor(): JwtRs() {
    override fun algorithm(): String = "RS256"
    override fun getSignature(): Signature = Signature.getInstance("SHA256withRSA")
}