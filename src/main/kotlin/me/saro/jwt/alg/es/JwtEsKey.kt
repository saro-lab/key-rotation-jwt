package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.util.*

data class JwtEsKey(
    val keyPair: KeyPair
): JwtKey {
    companion object {
        private val EN_BASE64 = Base64.getEncoder()
    }

    override fun stringify(): String =
        StringBuilder(500)
            .append(EN_BASE64.encodeToString(keyPair.public.encoded))
            .append(' ')
            .append(EN_BASE64.encodeToString(keyPair.private.encoded))
            .toString()
}
