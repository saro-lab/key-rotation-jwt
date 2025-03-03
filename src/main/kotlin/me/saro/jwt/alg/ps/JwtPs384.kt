package me.saro.jwt.alg.ps

import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class JwtPs384 internal constructor(): JwtPs() {
    override val algorithm: String = "PS384"
    override fun getSignature(): Signature = Signature.getInstance("RSASSA-PSS")
        .apply { setParameter(PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)) }
}