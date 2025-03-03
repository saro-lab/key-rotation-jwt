package me.saro.jwt.core

interface JwtAlgorithm {
    val algorithm: String
    fun toJwtKey(stringify: String): JwtKey
    fun signature(body: String, jwtKey: JwtKey): String
    fun verifySignature(jwtToken: List<String>, jwtKey: JwtKey): Boolean
    fun verifySignature(jwt: String, jwtKey: JwtKey): Boolean =
        verifySignature(jwt.split("."), jwtKey)
    fun with(jwtKey: JwtKey): Pair<JwtAlgorithm, JwtKey> = this to jwtKey
}
