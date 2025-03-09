package me.saro.jwt.store

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.Instant
import java.util.concurrent.locks.ReentrantReadWriteLock

class JwtMirrorKeyStore private constructor(
    private var list: Collection<JwtKeyStoreItem> = listOf()
): JwtKeyStore {
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    fun import(jsonArray: String): JwtKeyStore {
        val item = JwtKeyStoreItem.ofJsonArray(jsonArray, true)
        try {
            writeLock.lock()
            list = item
        } finally {
            writeLock.unlock()
        }
        return this
    }

    override fun getKeyStoreItem(): JwtKeyStoreItem =
        try {
            val now = Instant.now().epochSecond
            readLock.lock()
            list.find { it.notBefore <= now && it.expire > now }
        } finally {
            readLock.unlock()
        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found key")

    override fun findKeyStoreItem(kid: Long): JwtKeyStoreItem =
        try {
            readLock.lock()
            list.find { it.kid == kid }
        } finally {
            readLock.unlock()
        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")

    override fun export(): String =
        try {
            val now = Instant.now().epochSecond
            readLock.lock()
            list.filter { it.expire > now }.joinToString(",", "[", "]") { it.toJson() }
        } finally {
            readLock.unlock()
        }

    companion object {
        class Builder {
            private val store: JwtMirrorKeyStore = JwtMirrorKeyStore()

            fun import(jsonArray: String): Builder {
                store.import(jsonArray)
                return this
            }

            fun build(): JwtKeyStore {
                return store
            }
        }
    }
}