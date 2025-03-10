package me.saro.jwt.keyPair

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

abstract class JwtKeyPair(
    algorithm: JwtAlgorithm,
    option: JwtKeyOption = JwtKeyOption(),
): JwtKey(algorithm, option) {
    abstract val keyPair: KeyPair
    abstract fun getKeyPairSignature(): Signature

    val public: PublicKey get() = keyPair.public
    val publicKeySize: Int get() = public.encoded.size * 8
    val publicKeyString: String get() = JwtUtils.encodeToBase64String(public.encoded)

    val private: PrivateKey get() = keyPair.private
    val privateKeySize: Int get() = private.encoded.size * 8
    val privateKeyString: String get() = JwtUtils.encodeToBase64String(private.encoded)

    override val stringify: String get() = JwtUtils.writeValueAsString(mapOf(
        "algorithm" to algorithm.algorithmFullName,
        "kid" to kid,
        "notBefore" to notBefore,
        "expire" to expire,
        "publicKey" to publicKeyString,
        "privateKey" to privateKeyString
    ))

    override fun signature(body: ByteArray): ByteArray {
        val keyPairSignature = getKeyPairSignature()
        keyPairSignature.initSign(private)
        keyPairSignature.update(body)
        return JwtUtils.encodeToBase64UrlWop(keyPairSignature.sign())
    }

    override fun verifySignature(body: ByteArray, signature: ByteArray): Boolean = try {
        val keyPairSignature = getKeyPairSignature()
        keyPairSignature.initVerify(public)
        keyPairSignature.update(body)
        keyPairSignature.verify(JwtUtils.decodeBase64Url(signature))
    } catch (_: Exception) {
        false
    }
}
