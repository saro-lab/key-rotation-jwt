package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEs512: JwtEs() {
    companion object {
        private val ecGenParameterSpec = ECGenParameterSpec("secp521r1")
        private val signature = Signature.getInstance("SHA512withECDSAinP1363Format")
    }

    override fun algorithm(): String = "ES512"
    override fun getECGenParameterSpec(): ECGenParameterSpec = ecGenParameterSpec
    override fun getSignature(): Signature = signature
}