//package me.saro.jwt.java.alg;
//
//import me.saro.jwt.alg.hs.JwtHs256Algorithm;
//import me.saro.jwt.Jwt;
//import me.saro.jwt.JwtKey;
//import me.saro.jwt.JwtNode;
//import me.saro.jwt.exception.JwtException;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//
//import java.time.OffsetDateTime;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.UUID;
//
//@DisplayName("[Java] HS256")
//public class Hs256 {
//
//    JwtHs256Algorithm alg = Jwt.HS256;
//
//    @Test
//    @DisplayName("check jwt.io example")
//    public void t1() {
//        String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//        String secret = "your-256-bit-secret";
//        JwtKey key = alg.toJwtKey(secret);
//
//        System.out.println("example");
//        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));
//        System.out.println("example jwt toJwt - pass");
//
//        Assertions.assertThrows(JwtException.class, () -> Jwt.parse(jwt, node -> alg.with(alg.newRandomJwtKey())));
//        System.out.println("example jwt error text - pass");
//    }
//
//    @Test
//    @DisplayName("kid test")
//    public void t2() {
//
//        HashMap<String, JwtKey> keys = new HashMap<String, JwtKey>();
//        ArrayList<String> jwtList = new ArrayList<String>();
//
//        for (int i = 0 ; i < 30 ; i++) {
//            String kid = UUID.randomUUID().toString();
//            JwtKey key = alg.newRandomJwtKey();
//            keys.put(kid, key);
//
//            jwtList.add(Assertions.assertDoesNotThrow(() ->
//                    Jwt.builder()
//                            .kid(kid)
//                            .id("abc")
//                            .expire(OffsetDateTime.now().plusMinutes(30))
//                            .toJwt(alg, key)
//            ));
//        }
//
//        jwtList.parallelStream().forEach(jwt -> {
//            Assertions.assertThrows(JwtException.class, () -> Jwt.parse(jwt, node -> alg.with(alg.newRandomJwtKey())));
//            System.out.println(jwt);
//            JwtNode jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(keys.get(node.getKid()))));
//            Assertions.assertEquals("abc", jwtNode.getId());
//        });
//        System.out.println("done");
//    }
//
//    @Test
//    @DisplayName("expire test")
//    public void t3() {
//        JwtKey key = alg.newRandomJwtKey();
//
//        String jwtPass = Jwt.builder().expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
//        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));
//
//        String jwtFail = Jwt.builder().expire(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
//        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
//    }
//
//    @Test
//    @DisplayName("not before test")
//    public void t4() {
//        JwtKey key = alg.newRandomJwtKey();
//
//        String jwtPass = Jwt.builder().notBefore(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
//        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));
//
//        String jwtFail = Jwt.builder().notBefore(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
//        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
//    }
//
//    @Test
//    @DisplayName("data test")
//    public void t5() {
//
//        JwtKey key = alg.newRandomJwtKey();
//
//        String jwt = Jwt.builder()
//                .issuedAt(OffsetDateTime.now())
//                .notBefore(OffsetDateTime.now().minusMinutes(1))
//                .expire(OffsetDateTime.now().plusMinutes(30))
//                .id("jti value")
//                .issuer("iss value")
//                .subject("sub value")
//                .audience("aud value")
//                .claim("custom", "custom value")
//                .toJwt(alg, key);
//
//        System.out.println(jwt);
//
//        JwtNode jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));
//
//        System.out.println(jwtNode);
//
//        Assertions.assertEquals("jti value", jwtNode.getId());
//        Assertions.assertEquals("iss value", jwtNode.getIssuer());
//        Assertions.assertEquals("sub value", jwtNode.getSubject());
//        Assertions.assertEquals("aud value", jwtNode.getAudience());
//        Assertions.assertEquals("custom value", jwtNode.claim("custom"));
//    }
//}
