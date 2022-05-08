package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*

class JwtUtils {
    companion object {
        private val OBJECT_MAPPER = ObjectMapper()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}

        fun toJsonString(obj: Any): String = OBJECT_MAPPER.writeValueAsString(obj)

        fun encodeBase64UrlWop(obj: Any): String =
            EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(obj))

        /** jwt data is header + payload */
        fun toJwtData(header: Map<String, Any>, claims: Map<String, Any>): String =
            StringBuilder(200)
                .append(encodeBase64UrlWop(header))
                .append('.')
                .append(encodeBase64UrlWop(claims))
                .toString()

        @Throws(JwtException::class)
        fun toJwtHeader(jwt: String?): JwtHeader = try {
            JwtHeader(OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwt!!.substring(0, jwt!!.indexOf('.'))), TYPE_MAP))
        } catch (e: Exception) {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }

        @Throws(JwtException::class)
        fun toJwtClaimsWithoutVerify(jwt: String?): JwtClaims = try {
            JwtClaims(OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwt!!.substring(jwt!!.indexOf('.') + 1, jwt!!.lastIndexOf('.'))), TYPE_MAP))
        } catch (e: Exception) {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}