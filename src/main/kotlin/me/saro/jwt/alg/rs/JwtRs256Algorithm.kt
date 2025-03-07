package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs256Algorithm internal constructor(): JwtRsAlgorithm() {
    override val fullname: String = "RS256"
    override fun getSignature(): Signature = Signature.getInstance("SHA256withRSA")
}