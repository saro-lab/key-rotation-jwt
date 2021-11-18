package me.saro.jwt.core

interface JwtAlgorithm {

    fun verify(key: JwtKey, jwt: String, jwtObject: JwtObject): JwtObject

    fun verify(key: JwtKey, jwt: String): JwtObject =
        verify(key, jwt, JwtObject.parse(jwt))


    fun algorithm(): String
    fun signature(key: JwtKey, body: String): String

    fun randomJwtKey(): JwtKey
    fun parseJwtKey(text: String): JwtKey

    fun createJwtObject(): JwtObject =
        JwtObject.create(algorithm())

    fun toJwt(jwtKey: JwtKey, jwtObject: JwtObject): String =
        jwtObject.toJwtBody().run {
            this + '.' + signature(jwtKey, this)
        }
}
