package me.saro.jwt.exception

enum class JwtExceptionCode {
    // PARSER
    PARSE_ERROR,

    // HEADER
    NOT_EQUALS_HEADER_ALGORITHM,

    // KEY
    JWT_KEY_IS_NULL,
    INVALID_SIGNATURE,

    // CLAIMS
    DATE_EXPIRED
}