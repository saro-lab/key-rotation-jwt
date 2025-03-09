package me.saro.jwt.store

import me.saro.jwt.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.locks.ReentrantReadWriteLock

class JwtMirrorKeyStore private constructor(
    private var list: Collection<JwtKeyStoreItem> = listOf()
): JwtKeyStore {
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    override val key: JwtKey
        get() = TODO("Not yet implemented")

    override fun import(jsonArray: String): JwtKeyStore {
        val item = JwtKeyStoreItem.ofJsonArray(jsonArray, true)
        try {
            writeLock.lock()
            list = item
        } finally {
            writeLock.unlock()
        }
        return this
    }

    override fun export(): String =
        try {
            readLock.lock()
            list.joinToString(",", "[", "]") { it.toJson() }
        } finally {
            readLock.unlock()
        }

    override fun findKey(kid: Long): JwtKey =
        try {
            readLock.lock()
            list.find { it.kid == kid }
        } finally {
            readLock.unlock()
        }?.key ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found kid: $kid")

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