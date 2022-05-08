package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.OffsetDateTime
import java.util.*

class JwtClaims constructor(
    private val claims: MutableMap<String, Any>
) {
    fun claim(key: String, value: Any): JwtClaims {
        claims[key] = value
        return this
    }
    fun claim(key: String): Any? = claims[key]

    fun issuer() = claim("iss")
    fun issuer(value: Any) = claim("iss", value)

    fun subject() = claim("sub") as String?
    fun subject(value: String) = claim("sub", value)

    fun audience() = claim("aud") as String?
    fun audience(value: String) = claim("aud", value)

    fun id() = claim("jti") as String?
    fun id(value: String) = claim("jti", value)

    fun notBefore() = claim("nbf")?.let { Date(1000L * it as Long) }
    fun notBefore(date: Date) = claim("nbf", date.time / 1000L)
    fun notBefore(date: OffsetDateTime) = claim("nbf", date.toEpochSecond())

    fun issuedAt() = claim("iat")?.let { Date(1000L * it as Long) }
    fun issuedAt(date: Date) = claim("iat", date.time / 1000L)
    fun issuedAt(date: OffsetDateTime) = claim("iat", date.toEpochSecond())

    fun expire() = claim("exp")?.let { Date(1000L * it as Long) }
    fun expire(date: Date) = claim("exp", date.time / 1000L)
    fun expire(date: OffsetDateTime) = claim("exp", date.toEpochSecond())

    override fun toString(): String = JwtUtils.toJsonString(claims)

    fun toMap(): Map<String, Any> = claims.toMutableMap()

    @Throws(JwtException::class)
    fun assertExpire() {
        if (expire() != null && expire()!!.before(Date())) {
            throw JwtException(JwtExceptionCode.DATE_EXPIRED)
        }
    }
}
