package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs256Algorithm: JwtEsAlgorithm() {
    companion object {
        private val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
        private val signature = Signature.getInstance("SHA256withECDSAinP1363Format")
    }

    override fun algorithm(): String = "ES256"
    override fun getECGenParameterSpec(): ECGenParameterSpec = ecGenParameterSpec
    override fun getSignature(): Signature = signature
}