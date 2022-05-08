package me.saro.jwt.exception

class JwtException(code: JwtExceptionCode, override val message: String? = code.toString()): RuntimeException(message)
