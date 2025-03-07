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

class Jwt {
    companion object {
        @JvmField val ES256: JwtEs256 = JwtEs256()
        @JvmField val ES384: JwtEs384 = JwtEs384()
        @JvmField val ES512: JwtEs512 = JwtEs512()

        @JvmField val RS256: JwtRs256 = JwtRs256()
        @JvmField val RS384: JwtRs384 = JwtRs384()
        @JvmField val RS512: JwtRs512 = JwtRs512()

        @JvmField val PS256: JwtPs256 = JwtPs256()
        @JvmField val PS384: JwtPs384 = JwtPs384()
        @JvmField val PS512: JwtPs512 = JwtPs512()

        @JvmField val HS256: JwtHs256 = JwtHs256()
        @JvmField val HS384: JwtHs384 = JwtHs384()
        @JvmField val HS512: JwtHs512 = JwtHs512()

        @Suppress("UNCHECKED_CAST")
        fun <T: JwtAlgorithm> getAlgorithm(algorithm: String): T = when (algorithm) {
            "ES256" -> ES256 as T
            "ES384" -> ES384 as T
            "ES512" -> ES512 as T
            "RS256" -> RS256 as T
            "RS384" -> RS384 as T
            "RS512" -> RS512 as T
            "PS256" -> PS256 as T
            "PS384" -> PS384 as T
            "PS512" -> PS512 as T
            "HS256" -> HS256 as T
            "HS384" -> HS384 as T
            "HS512" -> HS512 as T
            else -> throw IllegalArgumentException("not support algorithm: $algorithm")
        }

        @JvmStatic
        fun builder(): Builder = Builder()

        @JvmStatic
        fun parse(jwt: String?, getAlgorithmWithKey: (jwtNode: JwtNode) -> Pair<JwtAlgorithm, JwtKey>): JwtNode =
            JwtNode.parse(jwt, getAlgorithmWithKey)

        @JvmStatic
        fun parseOrNull(jwt: String?, getAlgorithmWithKey: (jwtNode: JwtNode) -> Pair<JwtAlgorithm, JwtKey>): JwtNode? =
            try {
                JwtNode.parse(jwt, getAlgorithmWithKey)
            } catch (_: Exception) {
                null
            }
    }
}