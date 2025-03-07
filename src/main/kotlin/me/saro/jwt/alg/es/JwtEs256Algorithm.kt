package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs256Algorithm internal constructor(): JwtEsAlgorithm() {
    override val fullname: String = "ES256"
    override val genParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp256r1")
    override fun getSignature(): Signature = Signature.getInstance("SHA256withECDSAinP1363Format")
}