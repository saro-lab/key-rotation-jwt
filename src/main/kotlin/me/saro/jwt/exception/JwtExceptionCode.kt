package me.saro.jwt.exception

enum class JwtExceptionCode {
    // PARSER
    PARSE_ERROR,

    // KEY
    INVALID_SIGNATURE,

    // CLAIMS
    DATE_EXPIRED,
    DATE_BEFORE,
}