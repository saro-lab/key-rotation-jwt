//package me.saro.jwt.kotlin.alg
//
//import me.saro.jwt.alg.es.JwtEs512
//import org.junit.jupiter.api.Assertions
//import org.junit.jupiter.api.DisplayName
//import org.junit.jupiter.api.Test
//
//@DisplayName("[Kotlin] ES512")
//class ES512 {
//    @Test
//    @DisplayName("check jwt.io example")
//    fun t1() {
//        val exJwtBody = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
//        val exJwtSign = "AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk"
//        val publicKey = (
//                "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ" +
//                "PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47" +
//                "6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM" +
//                "Al8G7CqwoJOsW7Kddns="
//        )
//        val privateKey = (
//                "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga" +
//                "9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf" +
//                "Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN" +
//                "v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear" +
//                "jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12" +
//                "ew=="
//        )
//
//        val alg = JwtEs512()
//        val key = alg.parseJwtKey("$publicKey $privateKey")
//
//        val newJwtSign = alg.signature(exJwtBody, key)
//
//        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$exJwtSign", key) })
//        println(Assertions.assertDoesNotThrow<JwtObject> { alg.toJwtObjectWithVerify("$exJwtBody.$newJwtSign", key) })
//
//        Assertions.assertThrows(Exception::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign + "1", key) }
//        Assertions.assertThrows(Exception::class.java) { alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign + "1", key) }
//    }
//}