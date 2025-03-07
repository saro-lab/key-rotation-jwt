package me.saro.jwt

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
}
