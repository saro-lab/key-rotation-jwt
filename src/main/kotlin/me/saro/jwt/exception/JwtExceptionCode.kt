package me.saro.jwt.exception

enum class JwtExceptionCode {
    // PARSER
    PARSE_ERROR,

    // HEADER
    NOT_DEFINED_HEADER_ALGORITHM,
    NOT_EQUALS_HEADER_ALGORITHM,

    // CLAIMS
    EXPIRED_DATE
}