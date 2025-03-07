package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs512Algorithm internal constructor(): JwtHsAlgorithm() {
    override fun getKeyAlgorithm(): String = "HmacSHA512"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override val fullname: String = "HS512"
}