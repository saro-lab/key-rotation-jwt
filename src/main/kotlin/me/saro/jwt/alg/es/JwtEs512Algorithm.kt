package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs512Algorithm internal constructor(): JwtEsAlgorithm() {
    override val fullname: String = "ES512"
    override val genParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp521r1")
    override fun getSignature(): Signature = Signature.getInstance("SHA512withECDSAinP1363Format")
}