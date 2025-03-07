package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.spec.SecretKeySpec

abstract class JwtKey(
    open val jwtAlgorithm: JwtAlgorithm
) {
    companion object {
        private val EN_BASE64 = Base64.getEncoder()
    }

    abstract val keyAlgorithm: String
    abstract val stringify: String

    abstract fun newRandomJwtKey(): JwtKey

    val secret: SecretKeySpec get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "${jwtAlgorithm.algorithm} does not support secret key")
    val secretString: String get() = String(secret.encoded, Charsets.UTF_8)

    open val public: PublicKey get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "${jwtAlgorithm.algorithm} algorithm does not support public key")
    val publicKeySize: Int get() = public.encoded.size * 8
    val publicKeyString: String get() = EN_BASE64.encodeToString(public.encoded)

    open val private: PrivateKey  get() = throw JwtException(JwtExceptionCode.NOT_SUPPORT, "${jwtAlgorithm.algorithm} algorithm does not support private key")
    val privateKeySize: Int get() = private.encoded.size * 8
    val privateKeyString: String get() = EN_BASE64.encodeToString(private.encoded)
}
