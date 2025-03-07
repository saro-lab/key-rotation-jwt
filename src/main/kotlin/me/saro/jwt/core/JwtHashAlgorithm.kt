package me.saro.jwt.core

interface JwtHashAlgorithm : JwtAlgorithm {
//    companion object {
//        private val MOLD = "1234567890!@#$%^&*()+=-_/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
//        private val MOLD_LEN = MOLD.size
//    }

//    override fun verifySignature(body: ByteArray, signature: ByteArray, jwtKey: JwtKey): Boolean =
//        try {
//            signature(body, jwtKey).contentEquals(signature)
//        } catch (_: Exception) {
//            false
//        }
//
//    fun newRandomJwtKey(): JwtKey =
//        newRandomJwtKey(32, 64)
//
//    fun newRandomJwtKey(minLength: Int, maxLength: Int): JwtKey {
//        if (minLength > maxLength) {
//            throw IllegalArgumentException("maxLength must be greater than minLength")
//        }
//        val len = minLength + (Math.random() * (maxLength - minLength)).toInt()
//        val chars = CharArray(len)
//        for (i in 0 until len) {
//            chars[i] = MOLD[(Math.random() * MOLD_LEN).toInt()]
//        }
//        return toJwtKey(chars.toString())
//    }
}
