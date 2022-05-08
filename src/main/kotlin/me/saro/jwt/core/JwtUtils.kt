package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import java.util.*

class JwtUtils {
    companion object {
        private val OBJECT_MAPPER = ObjectMapper()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}

        fun encodeBase64UrlWop(obj: Any): String =
            EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(obj))
    }
}