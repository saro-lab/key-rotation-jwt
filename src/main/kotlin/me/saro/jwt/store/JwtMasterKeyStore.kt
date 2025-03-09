package me.saro.jwt.store

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.Duration
import java.time.Instant
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.ArrayDeque

class JwtMasterKeyStore private constructor(
    private val algorithm: JwtAlgorithm,
    private val genKey: (JwtAlgorithm) -> JwtKey = { it.newRandomJwtKey() },
    private val deque: ArrayDeque<JwtKeyStoreItem>,
): JwtKeyStore {
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    fun renew(): JwtMasterKeyStore {
        try {
            writeLock.lock()
            val kid = Instant.now().epochSecond
            JwtKeyStoreItem.of(kid, algorithm.createKey(), kid, kid, Long.MAX_VALUE).let {
                deque.add(it)
            }

            fun of(kid: Long, key: JwtKey, create: Long, notBefore: Long, expire: Long): JwtKeyStoreItem =
                JwtKeyStoreItem(kid, key, create, notBefore, expire)
            deque.add(keyStoreItem)
        } finally {
            writeLock.unlock()
        }
        return this
    }

    override fun getKeyStoreItem(): JwtKeyStoreItem =
        try {
            val now = Instant.now().epochSecond
            readLock.lock()
            deque.find { it.notBefore <= now && it.expire > now }
        } finally {
            readLock.unlock()
        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found key")

    override fun findKeyStoreItem(kid: Long): JwtKeyStoreItem =
        try {
            readLock.lock()
            deque.find { it.kid == kid }
        } finally {
            readLock.unlock()
        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")

    override fun export(): String =
        try {
            readLock.lock()
            deque.joinToString(",", "[", "]") { it.toJson() }
        } finally {
            readLock.unlock()
        }

    companion object {
        class Builder {
            private var jsonArray: String = "[]"
            private var algorithm: JwtAlgorithm? = null
            private var genKey: (JwtAlgorithm) -> JwtKey = { it.newRandomJwtKey() }
            private var keyLifetime: Duration? = null
            private var preparedBroadcastTime: Duration? = null
            private var minKeyCount: Duration? = null

            fun import(jsonArray: String): Builder {
                this.jsonArray = jsonArray
                return this
            }

            fun algorithm(algorithm: JwtAlgorithm, genKey: (JwtAlgorithm) -> JwtKey): Builder {
                this.algorithm = algorithm
                this.genKey = genKey
                return this
            }

            fun algorithm(algorithm: JwtAlgorithm): Builder {
                this.algorithm = algorithm
                return this
            }

            fun build(): JwtKeyStore {
                if (algorithm == null) {
                    throw JwtException(JwtExceptionCode.KEY_STORE_EXCEPTION, "algorithm is required")
                }

                val deque: ArrayDeque<JwtKeyStoreItem> = ArrayDeque()
                deque.addAll(JwtKeyStoreItem.ofJsonArray(jsonArray, true))

                val store: JwtMasterKeyStore = JwtMasterKeyStore(
                    algorithm!!,
                    genKey,
                    deque
                )
                return store
            }
        }
    }
}