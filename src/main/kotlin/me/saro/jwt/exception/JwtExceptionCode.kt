package me.saro.jwt.exception

enum class JwtExceptionCode {
    // PARSER
    PARSE_ERROR,

    // HEADER
    NOT_EQUALS_HEADER_ALGORITHM,

    // KEY
    INVALID_KEY,
    INVALID_SIGNATURE,

    // CLAIMS
    DATE_EXPIRED,

    // OTHER
    NOT_SUPPORT,
}