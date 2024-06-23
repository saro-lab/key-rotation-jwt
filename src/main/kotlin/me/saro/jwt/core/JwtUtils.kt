package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jsonMapper
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*

class JwtUtils {
    companion object {
        private val OBJECT_MAPPER: ObjectMapper = jsonMapper()
        private val DE_BASE64_URL: Base64.Decoder = Base64.getUrlDecoder()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}
        private val DE_BASE64: Base64.Decoder = Base64.getDecoder()

        private val EN_BASE64_URL_WOP: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

        @JvmStatic
        fun toJsonString(obj: Any): String = OBJECT_MAPPER.writeValueAsString(obj)

        @JvmStatic
        fun decodeBase64(src: String): ByteArray = DE_BASE64.decode(src)

        @JvmStatic
        fun decodeBase64Url(src: String): ByteArray = DE_BASE64_URL.decode(src)

        @JvmStatic
        fun encodeToBase64UrlWopString(src: ByteArray): String = EN_BASE64_URL_WOP.encodeToString(src)

        /** jwt data is header + payload */
        @JvmStatic
        fun toJwtData(header: Map<String, Any>, claims: Map<String, Any>): String =
            StringBuilder(200)
                .append(encodeToBase64UrlWopString(OBJECT_MAPPER.writeValueAsBytes(header)))
                .append('.')
                .append(encodeToBase64UrlWopString(OBJECT_MAPPER.writeValueAsBytes(claims)))
                .toString()

        @JvmStatic
        @Throws(JwtException::class)
        fun toJwtHeader(jwt: String?): JwtHeader = try {
            if (jwt.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR)
            }
            val token = jwt.split('.')
            if (token.size !in 2..3) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR)
            }
            JwtHeader(OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(token[0]), TYPE_MAP))
        } catch (e: Exception) {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }

        @JvmStatic
        @Throws(JwtException::class)
        fun toJwtClaimsWithoutVerify(jwt: String?): JwtClaims = try {
            if (jwt.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR)
            }
            val token = jwt.split('.')
            if (token.size !in 2..3) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR)
            }
            JwtClaims(OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(token[1]), TYPE_MAP))
        } catch (e: Exception) {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}