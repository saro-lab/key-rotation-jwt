package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import me.saro.jwt.exception.JwtException
import java.time.OffsetDateTime
import java.util.*

class JwtObject private constructor(
    private val header: MutableMap<String, Any>,
    private val claim: MutableMap<String, Any>
) {
    companion object {
        private val OBJECT_MAPPER = ObjectMapper()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}

        @JvmStatic
        fun create(alg: String): JwtObject {
            val header = mutableMapOf<String, Any>("typ" to "JWT", "alg" to alg)
            val claim = mutableMapOf<String, Any>("iat" to System.currentTimeMillis() / 1000L)
            return JwtObject(header, claim)
        }

        @JvmStatic
        fun parse(jwt: String): JwtObject {
            val jwtParts = jwt.split('.')
            val header = OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwtParts[0]), TYPE_MAP)
            val claim = OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwtParts[1]), TYPE_MAP)

            if (header["typ"] != "JWT") {
                throw JwtException("typ must be JWT : $jwt")
            }
            if (header["alg"] == null) {
                throw JwtException("alg is required : $jwt")
            }

            norDate(jwt, claim, "nbf")
            norDate(jwt, claim, "iat")
            norDate(jwt, claim, "exp")

            val exp = claim["exp"]
            if (exp != null && (System.currentTimeMillis() / 1000L) > (exp as Long)) {
                throw JwtException("expired jwt : $jwt")
            }
            return JwtObject(header, claim)
        }

        private fun norDate(jwt: String, claim: MutableMap<String, Any>, key: String) {
            var date = claim[key]
            if (date != null) {
                if (date is Int) {
                    date = date.toLong()
                    claim[key] = date
                }
                if (date !is Long) {
                    throw JwtException("nbf format error : $jwt")
                }
            }
        }
    }

    fun header(key: String, value: Any): JwtObject {
        when (key) {
            "alg" -> throw JwtException("alg(algorithm) is readonly")
            "typ" -> throw JwtException("tpy(type) is readonly")
        }
        header[key] = value
        return this
    }
    fun header(key: String): Any? = header[key]

    fun claim(key: String, value: Any): JwtObject {
        claim[key] = value
        return this
    }
    fun claim(key: String): Any? = claim[key]

    fun kid(): String? = header("kid") as String?
    fun kid(value: String) = header("kid", value)

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

    override fun toString(): String =
        OBJECT_MAPPER.writeValueAsString(header) + " " + OBJECT_MAPPER.writeValueAsString(claim)

    fun toJwtBody(): String =
        StringBuilder(200)
            .append(EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(header)))
            .append('.')
            .append(EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(claim)))
            .toString()
}
