package me.saro.jwt.alg.ps

import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class JwtPs512 internal constructor(): JwtPs() {
    override fun algorithm(): String = "PS512"
    override fun getSignature(): Signature = Signature.getInstance("RSASSA-PSS")
        .apply { setParameter(PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)) }
}