package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import me.saro.jwt.exception.JwtError
import me.saro.jwt.exception.JwtException

abstract class AbstractJwtAlgorithm: JwtAlgorithm {
    companion object {
        val OBJECT_MAPPER = ObjectMapper()
        val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}
    }

    @Throws(JwtException::class)
    override fun toJwtHeader(jwt: String?): JwtHeader = try {
        JwtHeader(OBJECT_MAPPER.readValue(jwt!!.substring(0, jwt!!.indexOf('.')), TYPE_MAP))
    } catch (e: Exception) {
        throw JwtException(JwtError.PARSE_ERROR)
    }

    @Throws(JwtException::class)
    override fun toJwtClaims(jwt: String?): JwtClaims = try {
        JwtClaims(OBJECT_MAPPER.readValue(jwt!!.substring(jwt!!.indexOf('.') + 1, jwt!!.lastIndexOf('.')), TYPE_MAP))
    } catch (e: Exception) {
        throw JwtException(JwtError.PARSE_ERROR)
    }
}
