package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs256Algorithm: JwtHsAlgorithm() {
    override fun getKeyAlgorithm(): String = "HmacSHA256"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override fun algorithm(): String = "HS256"
}