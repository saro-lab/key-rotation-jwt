package me.saro.jwt

abstract class JwtKey(
    private val data: JwtKeyData,
) {
    val algorithm: JwtAlgorithm = Jwt.getAlgorithm(data.algorithm)
    val kid: String get() = data.kid
    val notBefore: Long get() = data.notBefore
    val expire: Long get() = data.expire

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    abstract val stringify: String
    abstract fun signature(body: ByteArray): ByteArray
    abstract fun verifySignature(body: ByteArray, signature: ByteArray): Boolean
}
