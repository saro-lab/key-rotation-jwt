package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs512 internal constructor(): JwtEs() {
    override val algorithm: String = "ES512"
    override fun getECGenParameterSpec(): ECGenParameterSpec = ECGenParameterSpec("secp521r1")
    override fun getSignature(): Signature = Signature.getInstance("SHA512withECDSAinP1363Format")
}