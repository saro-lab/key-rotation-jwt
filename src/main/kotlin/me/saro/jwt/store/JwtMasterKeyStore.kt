package me.saro.jwt.store

import me.saro.jwt.JwtKey
import java.time.OffsetDateTime
import java.util.concurrent.ConcurrentLinkedDeque

class JwtMasterKeyStore(

): JwtKeyStore {
    override val key: JwtKey
        get() = TODO("Not yet implemented")

    override fun import(jsonArray: String): JwtKeyStore {
        TODO("Not yet implemented")
    }

    override fun export(): String {
        TODO("Not yet implemented")
    }

    override fun findKey(kid: String): JwtKey {
        TODO("Not yet implemented")
    }

    companion object {
        class Builder {
            private var initList: Collection<JwtKeyStoreItem> = listOf()

            fun build(): JwtKeyStore {
                val now = OffsetDateTime.now().toEpochSecond()
                initList.stream().filter { it.expire > now }
                return JwtKeyStore(ConcurrentLinkedDeque(initList))
            }
        }
    }
}