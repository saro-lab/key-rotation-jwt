package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs512Algorithm internal constructor(): JwtRsAlgorithm() {
    override val fullname: String = "RS512"
    override fun getSignature(): Signature = Signature.getInstance("SHA512withRSA")
}