//package me.saro.jwt.store
//
//import me.saro.jwt.JwtAlgorithm
//import me.saro.jwt.JwtKey
//import me.saro.jwt.exception.JwtException
//import me.saro.jwt.exception.JwtExceptionCode
//import java.time.Duration
//import java.time.Instant
//import java.util.concurrent.locks.ReentrantReadWriteLock
//import java.util.ArrayDeque
//
//class JwtKeyStoreProvider private constructor(
//    private val algorithm: JwtAlgorithm,
//    private val genKey: (JwtAlgorithm) -> JwtKey = { it.newRandomJwtKey() },
//    private val deque: ArrayDeque<JwtKey>,
//    private val keySyncTime: Duration,
//    private val keyExpireTime: Duration,
//): JwtKeyStore {
//    private val lock = ReentrantReadWriteLock()
//    private val writeLock = lock.writeLock()
//    private val readLock = lock.readLock()
//
//    override fun getKey(): JwtKey =
//        try {
//            val now = Instant.now().epochSecond
//            readLock.lock()
//            deque.find { it.notBefore <= now && it.expire > now }
//        } finally {
//            readLock.unlock()
//        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found key")
//
//    override fun findKey(kid: String): JwtKey =
//        try {
//            readLock.lock()
//            deque.find { it.kid == kid }
//        } finally {
//            readLock.unlock()
//        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")
//
//    override fun export(): String =
//        try {
//            val now = Instant.now().epochSecond
//            readLock.lock()
//            deque.filter { it.expire > now }.joinToString(",", "[", "]") { it.stringify }
//        } finally {
//            readLock.unlock()
//        }
//
////    fun renew(): JwtKeyStoreProvider {
////        try {
////            writeLock.lock()
////            val kid = Instant.now().epochSecond
////            JwtKey.of(kid, algorithm.createKey(), kid, kid, Long.MAX_VALUE).let {
////                deque.add(it)
////            }
////
////            fun of(kid: Long, key: JwtKey, create: Long, notBefore: Long, expire: Long): JwtKey =
////                JwtKey(kid, key, create, notBefore, expire)
////            deque.add(key)
////        } finally {
////            writeLock.unlock()
////        }
////        return this
////    }
////
////    fun addKey(key: JwtKey): JwtKeyStoreProvider {
////        try {
////            writeLock.lock()
////            deque.add(key)
////        } finally {
////            writeLock.unlock()
////        }
////        return this
////    }
//
//
//    companion object {
//        class Builder {
//            private var jsonArray: String = "[]"
//            private var algorithm: JwtAlgorithm? = null
//            private var genKey: (JwtAlgorithm) -> JwtKey = { it.newRandomJwtKey() }
//            private var keyLifetime: Duration? = null
//            private var preparedBroadcastTime: Duration? = null
//            private var minKeyCount: Duration? = null
//
//            fun import(jsonArray: String): Builder {
//                this.jsonArray = jsonArray
//                return this
//            }
//
//            fun algorithm(algorithm: JwtAlgorithm, genKey: (JwtAlgorithm) -> JwtKey): Builder {
//                this.algorithm = algorithm
//                this.genKey = genKey
//                return this
//            }
//
//            fun algorithm(algorithm: JwtAlgorithm): Builder {
//                this.algorithm = algorithm
//                return this
//            }
//
//            fun build(): JwtKeyStore {
//                if (algorithm == null) {
//                    throw JwtException(JwtExceptionCode.KEY_STORE_EXCEPTION, "algorithm is required")
//                }
//
//                val deque: ArrayDeque<JwtKey> = ArrayDeque()
//                deque.addAll(JwtKey.ofJsonArray(jsonArray, true))
//
//                val store: JwtKeyStoreProvider = JwtKeyStoreProvider(
//                    algorithm!!,
//                    genKey,
//                    deque
//                )
//                return store
//            }
//        }
//    }
//
//
//}