package me.saro.jwt.keyPair

import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature

interface JwtKeyPair: JwtKey {
    val keyPair: KeyPair

    val public: PublicKey get() = keyPair.public
    val publicKeySize: Int get() = public.encoded.size * 8
    val publicKeyString: String get() = JwtUtils.encodeToBase64String(public.encoded)

    val private: PrivateKey get() = keyPair.private
    val privateKeySize: Int get() = private.encoded.size * 8
    val privateKeyString: String get() = JwtUtils.encodeToBase64String(private.encoded)

    fun getKeyPairSignature(): Signature

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
