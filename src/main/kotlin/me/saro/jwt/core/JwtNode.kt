package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.io.ByteArrayOutputStream
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

open class JwtNode internal constructor(
    protected open val header: Map<String, String>,
    protected open val payload: Map<String, Any>,
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

    fun toBuilder(): Builder = Builder(header.toMutableMap(), payload.toMutableMap())

    override fun toString(): String {
        return "$header.$payload"
    }

    companion object {
        private const val DOT_BYTE: Byte = '.'.code.toByte()
        private const val DOT_INT: Int = '.'.code

        fun parse(jwt: String?, getAlgorithmWithKey: (jwtNode: JwtNode) -> Pair<JwtAlgorithm, JwtKey>): JwtNode {
            if (jwt.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt is null or blank")
            }
            val jwtByte = jwt.toByteArray()
            val firstDot = jwtByte.indexOf(DOT_BYTE)
            val lastDot = jwtByte.lastIndexOf(DOT_BYTE)
            if (firstDot == lastDot) {
                // 이 조건에 걸리는경우는 jwt가 header.payload.signature 형식이 아닌경우이다
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt must be header.payload.signature: $jwt")
            }
            val header: MutableMap<String, String> = try {
                JwtUtils.readTextMap(JwtUtils.decodeBase64Url(jwtByte.copyOfRange(0, firstDot)))
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "header parse error: $jwt")
            }
            val payload: MutableMap<String, Any> = try {
                JwtUtils.readMap(JwtUtils.decodeBase64Url(jwtByte.copyOfRange(firstDot + 1, lastDot)));
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "payload parse error: $jwt")
            }
            val jwtNode: JwtNode = JwtNode(header, payload)
            if (jwtNode.algorithm.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "algorithm is null or blank: $jwt, $JwtNode")
            }
            jwtNode.expire?.also {
                if (it.time < System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_EXPIRED, "jwt is expired: $jwt, $JwtNode")
                }
            }
            jwtNode.notBefore?.also {
                if (it.time > System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_BEFORE, "jwt is not before: $jwt, $JwtNode")
                }
            }
            try {
                if (getAlgorithmWithKey(jwtNode).let { (algorithm, key) -> algorithm.verifySignature(jwtByte.copyOfRange(0, lastDot), jwtByte.copyOfRange(lastDot + 1, jwt.length), key) }) {
                    return jwtNode
                }
            } catch (_: Exception) { }
            throw JwtException(JwtExceptionCode.INVALID_SIGNATURE, "signature verify error: $jwt, $JwtNode")
        }
    }

    open class Builder(
        override val header: MutableMap<String, String> = mutableMapOf("typ" to "JWT"),
        override val payload: MutableMap<String, Any> = mutableMapOf(),
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

            val jwt = ByteArrayOutputStream(10)
            jwt.write(JwtUtils.encodeToBase64UrlWop(JwtUtils.writeValueAsBytes(header)))
            jwt.write(DOT_INT)
            jwt.write(JwtUtils.encodeToBase64UrlWop(JwtUtils.writeValueAsBytes(payload)))
            val sig = algorithm.signature(jwt.toByteArray(), key)
            jwt.write(DOT_INT)
            jwt.write(sig)

            return String(jwt.toByteArray())
        }

        override fun toString(): String {
            return "$header.$payload"
        }
    }

}
