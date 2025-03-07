package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs384 internal constructor(): JwtEs() {
    override val algorithm: String = "ES384"
    override val genParameterSpec: ECGenParameterSpec = ECGenParameterSpec("secp384r1")
    override fun getSignature(): Signature = Signature.getInstance("SHA384withECDSAinP1363Format")
}