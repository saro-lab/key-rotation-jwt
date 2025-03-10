package me.saro.jwt.keyPair

import me.saro.jwt.JwtAlgorithm
import java.security.KeyPair
import java.security.Signature

class JwtRsKey internal constructor(
    jwtAlgorithm: JwtAlgorithm,
    override val keyPair: KeyPair
): JwtKeyPair(jwtAlgorithm) {
    override fun getKeyPairSignature(): Signature = (algorithm as JwtRsAlgorithm).getKeyPairSignature()
}