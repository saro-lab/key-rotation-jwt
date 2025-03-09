package me.saro.jwt

interface JwtKey {
    val stringify: String
    fun signature(body: ByteArray): ByteArray
    val algorithm: JwtAlgorithm
    fun verifySignature(body: ByteArray, signature: ByteArray): Boolean
    fun createJwt(): JwtNode.Builder = JwtNode.Builder(this)
}
