package me.saro.jwt

interface JwtKey {
    var kid: String
    var notBefore: Long
    var expire: Long
    val stringify: String
    fun signature(body: ByteArray): ByteArray
    val algorithm: JwtAlgorithm
    fun verifySignature(body: ByteArray, signature: ByteArray): Boolean
}
