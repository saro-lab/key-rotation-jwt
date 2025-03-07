package me.saro.jwt.core

import me.saro.jwt.alg.es.JwtEs256Algorithm
import me.saro.jwt.alg.es.JwtEs384Algorithm
import me.saro.jwt.alg.es.JwtEs512Algorithm
import me.saro.jwt.alg.hs.JwtHs256Algorithm
import me.saro.jwt.alg.hs.JwtHs384Algorithm
import me.saro.jwt.alg.hs.JwtHs512Algorithm
import me.saro.jwt.alg.ps.JwtPs256Algorithm
import me.saro.jwt.alg.ps.JwtPs384Algorithm
import me.saro.jwt.alg.ps.JwtPs512Algorithm
import me.saro.jwt.alg.rs.JwtRs256Algorithm
import me.saro.jwt.alg.rs.JwtRs384Algorithm
import me.saro.jwt.alg.rs.JwtRs512Algorithm
import me.saro.jwt.core.JwtNode.Builder

class Jwt {
    companion object {
        @JvmField val ES256: JwtEs256Algorithm = JwtEs256Algorithm()
        @JvmField val ES384: JwtEs384Algorithm = JwtEs384Algorithm()
        @JvmField val ES512: JwtEs512Algorithm = JwtEs512Algorithm()

        @JvmField val RS256: JwtRs256Algorithm = JwtRs256Algorithm()
        @JvmField val RS384: JwtRs384Algorithm = JwtRs384Algorithm()
        @JvmField val RS512: JwtRs512Algorithm = JwtRs512Algorithm()

        @JvmField val PS256: JwtPs256Algorithm = JwtPs256Algorithm()
        @JvmField val PS384: JwtPs384Algorithm = JwtPs384Algorithm()
        @JvmField val PS512: JwtPs512Algorithm = JwtPs512Algorithm()

        @JvmField val HS256: JwtHs256Algorithm = JwtHs256Algorithm()
        @JvmField val HS384: JwtHs384Algorithm = JwtHs384Algorithm()
        @JvmField val HS512: JwtHs512Algorithm = JwtHs512Algorithm()

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