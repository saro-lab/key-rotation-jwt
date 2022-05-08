package me.saro.jwt.alg.hs

import me.saro.jwt.core.AbstractJwtAlgorithm
import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtClaims
import me.saro.jwt.core.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.util.*
import java.util.function.Function
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

abstract class JwtHs: AbstractJwtAlgorithm() {
    companion object {
        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
        private val MOLD_LEN = MOLD.size
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
    }

    abstract fun getKeyAlgorithm(): String

    override fun toJwt(jwtClaims: JwtClaims, header: Map<String, Any>): String {
        TODO("Not yet implemented")
    }

    override fun verify(jwt: String, key: JwtKey): Boolean {
        TODO("Not yet implemented")
    }

    @Throws(JwtException::class)
    override fun toJwtKey(key: String): JwtKey = try {
        val point = key.indexOf(':')
        JwtHsKey(SecretKeySpec((key.substring(point + 1)).toByteArray(Charsets.UTF_8), key.substring(0, point)))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun newRandomJwtKey(): JwtKey =
        getJwtKey(32, 64)

    fun getJwtKey(secret: String): JwtKey =
        JwtHsKey(SecretKeySpec(secret.toByteArray(), getKeyAlgorithm()))

    fun getJwtKey(minLength: Int, maxLength: Int): JwtKey {
        if (minLength > maxLength) {
            throw IllegalArgumentException("maxLength must be greater than minLength")
        }
        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
        val chars = CharArray(len)
        for (i in 0 until len) {
            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
        }
        return getJwtKey(chars.toString())
    }

//    fun signature(body: String, jwtKey: JwtKey): String {
//        val mac = getMac()
//            .apply { init((jwtKey as JwtHsKey).key) }
//        return EN_BASE64_URL_WOP.encodeToString(mac.doFinal(body.toByteArray()))
//    }



//    abstract fun getKeyAlgorithm(): String
//
//    abstract fun getMac(): Mac
//

//

//

//

//
//    override fun toJwtObjectWithVerify(jwt: String, searchJwtKey: Function<Any?, JwtKey?>): JwtObject {
//        val jwtObject = JwtObject.parse(jwt)
//        val jwtKey = searchJwtKey.apply(jwtObject.kid())
//            ?: throw JwtException("does not found kid : ${jwtObject.kid()}")
//        if (jwtObject.header("alg") != algorithm()) {
//            throw JwtException("algorithm does not matched jwt : $jwt")
//        }
//        val firstPoint = jwt.indexOf('.')
//        val lastPoint = jwt.lastIndexOf('.')
//        if (firstPoint < lastPoint && firstPoint != -1) {
//            if (signature(jwt.substring(0, lastPoint), jwtKey) == jwt.substring(lastPoint + 1)) {
//                return jwtObject
//            }
//        }
//        throw JwtException("invalid jwt : $jwt")
//    }
//
//    override fun parseJwtKey(keyData: String): JwtKey {

//    }
}
