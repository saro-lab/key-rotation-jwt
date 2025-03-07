package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs512Algorithm;
import me.saro.jwt.Jwt;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.core.JwtNode;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

@DisplayName("[Java] ES512")
public class Es512 {

    JwtEs512Algorithm alg = Jwt.ES512;

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        String jwt = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AbVUinMiT3J_03je8WTOIl-VdggzvoFgnOsdouAs-DLOtQzau9valrq-S6pETyi9Q18HH-EuwX49Q7m3KC0GuNBJAc9Tksulgsdq8GqwIqZqDKmG7hNmDzaQG1Dpdezn2qzv-otf3ZZe-qNOXUMRImGekfQFIuH_MjD2e8RZyww6lbZk";
        String publicKey = "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZPDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib476MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwMAl8G7CqwoJOsW7Kddns=";
        String privateKey = "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxfZ6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12ew==";

        JwtKey key = alg.toJwtKey(publicKey, privateKey);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> Jwt.parse(jwt, node -> alg.with(alg.newRandomJwtKey())));
        System.out.println("example jwt error text - pass");
    }

    @Test
    @DisplayName("kid test")
    public void t2() {

        HashMap<String, JwtKey> keys = new HashMap<String, JwtKey>();
        ArrayList<String> jwtList = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            String kid = UUID.randomUUID().toString();
            JwtKey key = alg.newRandomJwtKey();
            keys.put(kid, key);

            jwtList.add(Assertions.assertDoesNotThrow(() ->
                    Jwt.builder()
                            .kid(kid)
                            .id("abc")
                            .expire(OffsetDateTime.now().plusMinutes(30))
                            .toJwt(alg, key)
            ));
        }

        jwtList.parallelStream().forEach(jwt -> {
            Assertions.assertThrows(JwtException.class, () -> Jwt.parse(jwt, node -> alg.with(alg.newRandomJwtKey())));
            System.out.println(jwt);
            JwtNode jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(keys.get(node.getKid()))));
            Assertions.assertEquals("abc", jwtNode.getId());
        });
        System.out.println("done");
    }

    @Test
    @DisplayName("expire test")
    public void t3() {
        JwtKey key = alg.newRandomJwtKey();

        String jwtPass = Jwt.builder().expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));

        String jwtFail = Jwt.builder().expire(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
    }

    @Test
    @DisplayName("not before test")
    public void t4() {
        JwtKey key = alg.newRandomJwtKey();

        String jwtPass = Jwt.builder().notBefore(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));

        String jwtFail = Jwt.builder().notBefore(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
    }

    @Test
    @DisplayName("data test")
    public void t5() {

        JwtKey key = alg.newRandomJwtKey();

        String jwt = Jwt.builder()
                .issuedAt(OffsetDateTime.now())
                .notBefore(OffsetDateTime.now().minusMinutes(1))
                .expire(OffsetDateTime.now().plusMinutes(30))
                .id("jti value")
                .issuer("iss value")
                .subject("sub value")
                .audience("aud value")
                .claim("custom", "custom value")
                .toJwt(alg, key);

        System.out.println(jwt);

        JwtNode jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));

        System.out.println(jwtNode);

        Assertions.assertEquals("jti value", jwtNode.getId());
        Assertions.assertEquals("iss value", jwtNode.getIssuer());
        Assertions.assertEquals("sub value", jwtNode.getSubject());
        Assertions.assertEquals("aud value", jwtNode.getAudience());
        Assertions.assertEquals("custom value", jwtNode.claim("custom"));
    }
}
