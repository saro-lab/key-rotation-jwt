package me.saro.jwt.core

import me.saro.jwt.alg.es.JwtEs256
import me.saro.jwt.alg.es.JwtEs384
import me.saro.jwt.alg.es.JwtEs512
import me.saro.jwt.alg.hs.JwtHs256
import me.saro.jwt.alg.hs.JwtHs384
import me.saro.jwt.alg.hs.JwtHs512
import me.saro.jwt.alg.ps.JwtPs256
import me.saro.jwt.alg.ps.JwtPs384
import me.saro.jwt.alg.ps.JwtPs512
import me.saro.jwt.alg.rs.JwtRs256
import me.saro.jwt.alg.rs.JwtRs384
import me.saro.jwt.alg.rs.JwtRs512
import me.saro.jwt.core.JwtUtils.Companion.encodeToBase64UrlWopString
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode

class Jwt {
    companion object {
        @JvmStatic
        fun es256(): JwtEs256 = JwtEs256()
        @JvmStatic
        fun es384(): JwtEs384 = JwtEs384()
        @JvmStatic
        fun es512(): JwtEs512 = JwtEs512()

        @JvmStatic
        fun rs256(): JwtRs256 = JwtRs256()
        @JvmStatic
        fun rs384(): JwtRs384 = JwtRs384()
        @JvmStatic
        fun rs512(): JwtRs512 = JwtRs512()

        @JvmStatic
        fun ps256(): JwtPs256 = JwtPs256()
        @JvmStatic
        fun ps384(): JwtPs384 = JwtPs384()
        @JvmStatic
        fun ps512(): JwtPs512 = JwtPs512()

        @JvmStatic
        fun hs256(): JwtHs256 = JwtHs256()
        @JvmStatic
        fun hs384(): JwtHs384 = JwtHs384()
        @JvmStatic
        fun hs512(): JwtHs512 = JwtHs512()

        /** jwt data is header + payload */
        @JvmStatic
        fun toJwtData(header: Map<String, Any>, claims: Map<String, Any>): String =
            StringBuilder(200)
                .append(encodeToBase64UrlWopString(JwtUtils.writeValueAsBytes(header)))
                .append('.')
                .append(encodeToBase64UrlWopString(JwtUtils.writeValueAsBytes(claims)))
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
            JwtHeader(JwtUtils.readMap(JwtUtils.decodeBase64Url(token[0])))
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
            JwtClaims(JwtUtils.readMap(JwtUtils.decodeBase64Url(token[1])))
        } catch (e: Exception) {
            throw JwtException(JwtExceptionCode.PARSE_ERROR)
        }
    }
}