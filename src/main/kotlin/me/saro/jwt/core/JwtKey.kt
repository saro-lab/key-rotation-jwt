package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.spec.SecretKeySpec

interface JwtKey {
    companion object {
        private val EN_BASE64 = Base64.getEncoder()
    }
    val algorithm: String

    val secret: SecretKeySpec get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "$algorithm algorithm does not support secret key")
    val secretString: String get() = String(secret.encoded, Charsets.UTF_8)

    val public: PublicKey get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "$algorithm algorithm does not support public key")
    val private: PrivateKey  get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "$algorithm algorithm does not support private key")
    val publicKeyString: String get() = EN_BASE64.encodeToString(public.encoded)
    val privateKeyString: String get() = EN_BASE64.encodeToString(private.encoded)
}
