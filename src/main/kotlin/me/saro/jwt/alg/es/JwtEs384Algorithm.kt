package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtEsAlgorithm
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs384Algorithm internal constructor(): JwtEsAlgorithm() {
    override val fullname: String = "ES384"
    override val genParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp384r1")
    override fun getSignature(): Signature = Signature.getInstance("SHA384withECDSAinP1363Format")
}