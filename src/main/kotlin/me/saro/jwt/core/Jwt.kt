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
import me.saro.jwt.core.JwtNode.Builder
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

        @JvmStatic
        fun builder(): Builder =
            Builder(
                header = mutableMapOf<String, String>("typ" to "JWT"),
                payload = mutableMapOf<String, Any>(),
            )

        @JvmStatic
        fun parse(jwt: String?, getAlgorithmWithKey: (jwtNode: JwtNode) -> Pair<JwtAlgorithm, JwtKey>): JwtNode {
            if (jwt.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt is null or blank")
            }
            val token: List<String> = jwt.split('.')
            if (token.size != 3) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt must be header.payload.signature: $jwt")
            }
            if (token.any { it.isBlank() }) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt must be header.payload.signature: $jwt")
            }
            val header: MutableMap<String, String> = try {
                JwtUtils.readTextMap(JwtUtils.decodeBase64Url(token[0]));
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "header parse error: $jwt")
            }
            val payload: MutableMap<String, Any> = try {
                JwtUtils.readMap(JwtUtils.decodeBase64Url(token[1]));
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "payload parse error: $jwt")
            }
            val jwtNode: JwtNode = JwtNode(header, payload)
            jwtNode.expire?.also {
                if (it.time < System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_EXPIRED, "jwt is expired: $jwt")
                }
            }
            jwtNode.notBefore?.also {
                if (it.time > System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_BEFORE, "jwt is not before: $jwt")
                }
            }
            try {
                if (getAlgorithmWithKey(jwtNode).let { (algorithm, key) -> algorithm.verifySignature(token, key) }) {
                    return jwtNode
                }
            } catch (_: Exception) { }
            throw JwtException(JwtExceptionCode.INVALID_SIGNATURE, "signature verify error: $jwt")
        }
    }
}