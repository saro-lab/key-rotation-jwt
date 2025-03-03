package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs384 internal constructor(): JwtHs() {
    override fun getKeyAlgorithm(): String = "HmacSHA384"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override val algorithm: String = "HS384"
}