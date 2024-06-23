package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode

interface JwtAlgorithmPemKeyPair : JwtAlgorithm {
    @Throws(JwtException::class)
    fun toJwtKey(publicKey: String, privateKey: String): JwtKey

    override fun toJwtKeyByStringify(stringify: String): JwtKey = stringify.let {
        val iof = it.indexOf(' ')
        if (iof == -1) throw JwtException(JwtExceptionCode.INVALID_KEY, "invalid jwt key format")
        toJwtKey(it.substring(0, iof), it.substring(iof + 1))
    }

    fun newRandomJwtKey(bit: Int): JwtKey
}
