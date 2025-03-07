package me.saro.jwt

interface JwtKey{
    val stringify: String
    fun signature(body: ByteArray): ByteArray
    val algorithm: JwtAlgorithm

    fun verifySignature(body: ByteArray, signature: ByteArray): Boolean =
        try {
            signature(body).contentEquals(signature)
        } catch (_: Exception) {
            false
        }
}
