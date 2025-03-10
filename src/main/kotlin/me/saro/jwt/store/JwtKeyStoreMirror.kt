package me.saro.jwt.store

import me.saro.jwt.Jwt
import me.saro.jwt.JwtKey
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.Instant
import java.util.concurrent.locks.ReentrantReadWriteLock

class JwtKeyStoreMirror private constructor(
    private var list: Collection<JwtKey> = listOf()
): JwtKeyStore {
    private val lock = ReentrantReadWriteLock()
    private val writeLock = lock.writeLock()
    private val readLock = lock.readLock()

    fun import(jsonArray: String): JwtKeyStore {
        val now = Instant.now().epochSecond
        val item = Jwt.parseKeyArray(jsonArray).filter { it.expire > now }
        try {
            writeLock.lock()
            list = item
        } finally {
            writeLock.unlock()
        }
        return this
    }

    override fun getKey(): JwtKey =
        try {
            val now = Instant.now().epochSecond
            readLock.lock()
            list.find { it.notBefore <= now && it.expire > now }
        } finally {
            readLock.unlock()
        } ?: throw JwtException(JwtExceptionCode.NOT_FOUND_KEY, "not found key")

    override fun findKey(kid: String): JwtKey =
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
            list.filter { it.expire > now }.joinToString(",", "[", "]") { it.stringify }
        } finally {
            readLock.unlock()
        }

    companion object {
        class Builder {
            private val store: JwtKeyStoreMirror = JwtKeyStoreMirror()

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