package me.saro.jwt

import me.saro.jwt.hash.JwtHsAlgorithm
import me.saro.jwt.keyPair.JwtEsAlgorithm
import me.saro.jwt.keyPair.JwtKeyPairAlgorithm
import me.saro.jwt.keyPair.JwtPsAlgorithm
import me.saro.jwt.keyPair.JwtRsAlgorithm

class Jwt {
    companion object {
        @JvmField val ES256: JwtEsAlgorithm = JwtEsAlgorithm("ES256")
        @JvmField val ES384: JwtEsAlgorithm = JwtEsAlgorithm("ES384")
        @JvmField val ES512: JwtEsAlgorithm = JwtEsAlgorithm("ES512")

        @JvmField val RS256: JwtRsAlgorithm = JwtRsAlgorithm("RS256")
        @JvmField val RS384: JwtRsAlgorithm = JwtRsAlgorithm("RS384")
        @JvmField val RS512: JwtRsAlgorithm = JwtRsAlgorithm("RS512")

        @JvmField val PS256: JwtPsAlgorithm = JwtPsAlgorithm("PS256")
        @JvmField val PS384: JwtPsAlgorithm = JwtPsAlgorithm("PS384")
        @JvmField val PS512: JwtPsAlgorithm = JwtPsAlgorithm("PS512")

        @JvmField val HS256: JwtHsAlgorithm = JwtHsAlgorithm("HS256")
        @JvmField val HS384: JwtHsAlgorithm = JwtHsAlgorithm("HS384")
        @JvmField val HS512: JwtHsAlgorithm = JwtHsAlgorithm("HS512")

        @JvmStatic
        @Suppress("UNCHECKED_CAST")
        fun <T: JwtAlgorithm> getAlgorithm(algorithm: String?): T = when (algorithm) {
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
        fun parseJwt(jwt: String?, getJwtKey: (jwtNode: JwtNode) -> JwtKey?): JwtNode =
            JwtNode.parse(jwt, getJwtKey)

        @JvmStatic
        fun createJwt(jwtKey: JwtKey): JwtNode.Builder = JwtNode.Builder(jwtKey)

        @JvmStatic
        fun parseKey(stringify: String): JwtKey {
            val map: MutableMap<String, String> = JwtUtils.readTextMap(stringify)

            when (val algorithm = getAlgorithm<JwtAlgorithm>(map["algorithm"])) {
                is JwtKeyPairAlgorithm<*> -> {
                    return algorithm.toJwtKey(map["publicKey"]!!, map["privateKey"]!!)
                        .apply {
                            kid = map["kid"].toString()
                            notBefore = map["notBefore"].toString().toLong()
                            expire = map["expire"].toString().toLong()
                        }
                }

                is JwtHsAlgorithm -> {
                    return algorithm.toJwtKeyByBase64Url(map["secret"]!!)
                        .apply {
                            kid = map["kid"].toString()
                            notBefore = map["notBefore"].toString().toLong()
                            expire = map["expire"].toString().toLong()
                        }
                }

                else -> {
                    throw IllegalArgumentException("Unsupported algorithm: ${algorithm.algorithmFullName}")
                }
            }
        }

    }
}
