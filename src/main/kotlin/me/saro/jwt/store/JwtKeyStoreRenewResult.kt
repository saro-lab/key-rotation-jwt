package me.saro.jwt.store

class JwtKeyStoreRenewResult(
    val now: List<JwtKeyStoreItem>,
    val remove: List<JwtKeyStoreItem>,
    val add: List<JwtKeyStoreItem>,
    val update: List<JwtKeyStoreItem>,
    val pointer: JwtKeyStoreItem
)
