package me.saro.jwt

import java.util.*

abstract class JwtKey(
    val algorithm: JwtAlgorithm
) {
    internal var kidIn: String = UUID.randomUUID().toString()
    internal var notBeforeIn: Long = 0
    internal var expireIn: Long = 0

    val kid: String get() = kidIn
    val notBefore: Long get() = notBeforeIn
    val expire: Long get() = expireIn

    override fun toString(): String = stringify
    override fun hashCode(): Int = stringify.hashCode()
    override fun equals(other: Any?): Boolean = other is JwtKey && stringify == other.stringify

    abstract val stringify: String
    abstract fun signature(body: ByteArray): ByteArray
    abstract fun verifySignature(body: ByteArray, signature: ByteArray): Boolean
}
