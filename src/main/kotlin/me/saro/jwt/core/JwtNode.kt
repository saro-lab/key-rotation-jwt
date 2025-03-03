package me.saro.jwt.core

import me.saro.jwt.core.JwtUtils.Companion.encodeToBase64UrlWopString
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

open class JwtNode internal constructor(
    protected open val header: MutableMap<String, String>,
    protected open val payload: MutableMap<String, Any>,
) {
    fun header(key: String): String? = header[key]

    val kid: String? get() = header("kid")
    val type: String? get() = header("typ")
    val algorithm: String? get() = header("alg")

    @Suppress("UNCHECKED_CAST")
    fun <T> claim(key: String): T? = payload[key] as T?
    fun claimBoolean(key: String): Boolean? = when (val v = payload[key]) {
        null -> null
        is Boolean -> v
        is Int -> v != 0
        is Long -> v != 0L
        is String -> v.lowercase().matches("true|yes|on|1".toRegex())
        else -> v.toString().lowercase().matches("true|yes|on|1".toRegex())
    }
    fun claimInt(key: String): Int? = when (val v = payload[key]) {
        null -> null
        is Int -> v
        is Long -> v.toInt()
        is String -> if (v.isNotBlank()) v.toInt() else null
        else -> v.toString().toInt()
    }
    fun claimLong(key: String): Long? = when (val v = payload[key]) {
        null -> null
        is Int -> v.toLong()
        is Long -> v
        is String -> if (v.isNotBlank()) v.toLong() else null
        else -> v.toString().toLong()
    }
    fun claimDateByTimestamp(key: String): Date? = when (val v = payload[key]) {
        null -> null
        is Date -> v
        else -> claimLong(key)?.let { Date(1000L * it) }
    }

    val issuer: Any? get() = claim("iss")
    val subject: String? get() = claim("sub")
    val audience: String? get() = claim("aud")
    val id: String? get() = claim("jti")
    val notBefore: Date? get() = claimDateByTimestamp("nbf")
    val issuedAt: Date? get() = claimDateByTimestamp("iat")
    val expire: Date? get() = claimDateByTimestamp("exp")

    override fun toString(): String {
        return """
            |header: $header
            |payload: $payload
        """.trimIndent()
    }

    open class Builder(
        override val header: MutableMap<String, String>,
        override val payload: MutableMap<String, Any>,
    ): JwtNode(header, payload) {
        fun header(key: String, value: String): Builder = this.apply { header[key] = value }
        fun kid(value: String): Builder = this.apply { header["kid"] = value }

        fun claim(key: String, value: Any): Builder = this.apply { payload[key] = value }
        fun claimTimestamp(key: String, value: Date): Builder = claim(key, value.time / 1000L)
        fun claimTimestamp(key: String, value: OffsetDateTime): Builder = claim(key, value.toEpochSecond())
        fun claimTimestamp(key: String, value: ZonedDateTime): Builder = claim(key, value.toEpochSecond())

        fun issuer(value: Any): Builder = claim("iss", value)

        fun subject(value: String): Builder = claim("sub", value)

        fun audience(value: String): Builder = claim("aud", value)

        fun id(value: String): Builder = claim("jti", value)

        fun notBefore(date: Date): Builder = claimTimestamp("nbf", date)
        fun notBefore(date: OffsetDateTime): Builder = claimTimestamp("nbf", date)
        fun notBefore(date: ZonedDateTime): Builder = claimTimestamp("nbf", date)

        fun issuedAt(date: Date): Builder = claimTimestamp("iat", date)
        fun issuedAt(date: OffsetDateTime): Builder = claimTimestamp("iat", date)
        fun issuedAt(date: ZonedDateTime): Builder = claimTimestamp("iat", date)

        fun expire(date: Date): Builder = claimTimestamp("exp", date)
        fun expire(date: OffsetDateTime): Builder = claimTimestamp("exp", date)
        fun expire(date: ZonedDateTime): Builder = claimTimestamp("exp", date)

        fun toJwt(algorithm: JwtAlgorithm, key: JwtKey): String {
            header["alg"] = algorithm.algorithm

            val header = encodeToBase64UrlWopString(JwtUtils.writeValueAsBytes(header))
            val payload = encodeToBase64UrlWopString(JwtUtils.writeValueAsBytes(payload))

            return StringBuilder(1000)
                .append(header)
                .append('.')
                .append(payload)
                .append('.')
                .append(algorithm.signature(payload, key))
                .toString()
        }

        override fun toString(): String {
            return """
                |header: $header
                |payload: $payload
            """.trimIndent()
        }
    }
}
