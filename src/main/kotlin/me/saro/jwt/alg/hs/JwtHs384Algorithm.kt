package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs384Algorithm internal constructor(): JwtHsAlgorithm() {
    override fun getKeyAlgorithm(): String = "HmacSHA384"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override val fullname: String = "HS384"
}