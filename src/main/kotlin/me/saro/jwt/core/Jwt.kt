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