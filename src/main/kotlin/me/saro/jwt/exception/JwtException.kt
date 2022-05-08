package me.saro.jwt.exception

class JwtException(val code: JwtExceptionCode, override val message: String? = null): RuntimeException(message ?: code.toString())
