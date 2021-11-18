package me.saro.jwt.alg.hs

import javax.crypto.Mac

class JwtHs384: JwtHs() {
    override fun getKeyAlgorithm(): String = "HmacSHA384"
    override fun getMac(): Mac = Mac.getInstance(getKeyAlgorithm())
    override fun algorithm(): String = "HS384"
}