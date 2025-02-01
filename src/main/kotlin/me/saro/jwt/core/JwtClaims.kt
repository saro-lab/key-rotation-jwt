package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

class JwtClaims internal constructor(
    private val claims: MutableMap<String, Any>
) {
    companion object {
        @JvmStatic
        fun create(): JwtClaims {
            return JwtClaims(mutableMapOf())
        }
    }

    fun claim(key: String, value: Any): JwtClaims = this.apply { claims[key] = value }
    fun claimTimestamp(key: String, value: Date): JwtClaims = claim(key, value.time / 1000L)
    fun claimTimestamp(key: String, value: OffsetDateTime): JwtClaims = claim(key, value.toEpochSecond())
    fun claimTimestamp(key: String, value: ZonedDateTime): JwtClaims = claim(key, value.toEpochSecond())

    @Suppress("UNCHECKED_CAST")
    fun <T> claim(key: String): T? = claims[key] as T?
    fun claimBoolean(key: String): Boolean? = when (val v = claims[key]) {
        null -> null
        is Boolean -> v
        is Int -> v != 0
        is Long -> v != 0L
        is String -> v.lowercase().matches("true|yes|on|1".toRegex())
        else -> v.toString().lowercase().matches("true|yes|on|1".toRegex())
    }
    fun claimInt(key: String): Int? = when (val v = claims[key]) {
        null -> null
        is Int -> v
        is Long -> v.toInt()
        is String -> if (v.isNotBlank()) v.toInt() else null
        else -> v.toString().toInt()
    }
    fun claimLong(key: String): Long? = when (val v = claims[key]) {
        null -> null
        is Int -> v.toLong()
        is Long -> v
        is String -> if (v.isNotBlank()) v.toLong() else null
        else -> v.toString().toLong()
    }
    fun claimDateByTimestamp(key: String): Date? = when (val v = claims[key]) {
        null -> null
        is Date -> v
        else -> claimLong(key)?.let { Date(1000L * it) }
    }

    val issuer: Any? get() = claim("iss")
    fun issuer(value: Any): JwtClaims = claim("iss", value)

    val subject: String? get() = claim("sub")
    fun subject(value: String): JwtClaims = claim("sub", value)

    val audience: String? get() = claim("aud")
    fun audience(value: String): JwtClaims = claim("aud", value)

    val id: String? get() = claim("jti")
    fun id(value: String): JwtClaims = claim("jti", value)

    val notBefore: Date? get() = claimDateByTimestamp("nbf")
    fun notBefore(date: Date): JwtClaims = claimTimestamp("nbf", date)
    fun notBefore(date: OffsetDateTime): JwtClaims = claimTimestamp("nbf", date)
    fun notBefore(date: ZonedDateTime): JwtClaims = claimTimestamp("nbf", date)

    val issuedAt: Date? get() = claimDateByTimestamp("iat")
    fun issuedAt(date: Date): JwtClaims = claimTimestamp("iat", date)
    fun issuedAt(date: OffsetDateTime): JwtClaims = claimTimestamp("iat", date)
    fun issuedAt(date: ZonedDateTime): JwtClaims = claimTimestamp("iat", date)

    val expire: Date? get() = claimDateByTimestamp("exp")
    fun expire(date: Date): JwtClaims = claimTimestamp("exp", date)
    fun expire(date: OffsetDateTime): JwtClaims = claimTimestamp("exp", date)
    fun expire(date: ZonedDateTime): JwtClaims = claimTimestamp("exp", date)

    override fun toString(): String = JwtUtils.toJsonString(claims)

    fun toMap(): Map<String, Any> = claims.toMutableMap()

    @Throws(JwtException::class)
    fun validExpire() {
        if (expire != null && expire!!.before(Date())) {
            throw JwtException(JwtExceptionCode.DATE_EXPIRED)
        }
    }

    @Throws(JwtException::class)
    fun validNotBefore() {
        if (notBefore != null && notBefore!!.after(Date())) {
            throw JwtException(JwtExceptionCode.DATE_EXPIRED)
        }
    }

    fun valid() {
        validExpire()
        validNotBefore()
    }
}
