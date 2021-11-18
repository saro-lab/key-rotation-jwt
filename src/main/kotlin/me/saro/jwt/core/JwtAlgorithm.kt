package me.saro.jwt.core

interface JwtAlgorithm {
    fun algorithm(): String
    fun genJwtKey(): JwtKey
    fun signature(key: JwtKey, body: String): String
    fun verify(key: JwtKey, jwt: String, jwtObject: JwtObject): JwtObject
    fun toJwtKey(text: String): JwtKey

    fun verify(key: JwtKey, jwt: String): JwtObject =
        verify(key, jwt, JwtObject.parse(jwt))
}
