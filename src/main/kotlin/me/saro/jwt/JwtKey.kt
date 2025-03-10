package me.saro.jwt

abstract class JwtKey(
    val algorithm: JwtAlgorithm,
    private val option: JwtKeyOption
) {
    val kid: String get() = option.kid
    val notBefore: Long get() = option.notBefore
    val expire: Long get() = option.expire

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    abstract val stringify: String
    abstract fun signature(body: ByteArray): ByteArray
    abstract fun verifySignature(body: ByteArray, signature: ByteArray): Boolean
}
