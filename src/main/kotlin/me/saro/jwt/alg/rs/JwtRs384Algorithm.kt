package me.saro.jwt.alg.rs

import java.security.Signature

class JwtRs384Algorithm internal constructor(): JwtRsAlgorithm() {
    override val fullname: String = "RS384"
    override fun getSignature(): Signature = Signature.getInstance("SHA384withRSA")
}