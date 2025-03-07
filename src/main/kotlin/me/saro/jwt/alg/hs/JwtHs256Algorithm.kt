package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs256Algorithm internal constructor(): JwtHsAlgorithm() {
    override fun getKeyAlgorithm(): String = "HmacSHA256"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override val fullname: String = "HS256"
}