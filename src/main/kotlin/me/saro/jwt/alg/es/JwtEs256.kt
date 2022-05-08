//package me.saro.jwt.alg.es
//
//import java.security.Signature
//import java.security.spec.ECGenParameterSpec
//
//class JwtEs256: JwtEs() {
//    override fun algorithm(): String = "ES256"
//    override fun getECGenParameterSpec(): ECGenParameterSpec = ECGenParameterSpec("secp256r1")
//    override fun getSignature(): Signature = Signature.getInstance("SHA256withECDSAinP1363Format")
//}