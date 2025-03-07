//package me.saro.jwt.java.alg;
//
//import me.saro.jwt.impl.JwtHsAlgorithm;
//import me.saro.jwt.Jwt;
//import me.saro.jwt.JwtAlgorithm;
//import me.saro.jwt.JwtKey;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//
//import java.time.OffsetDateTime;
//import java.util.*;
//
//@DisplayName("[Java] HS Thread And Random KID Test")
//public class HsThreadTest {
//    @Test
//    @DisplayName("Thread And Random KID Test")
//    public void t1() {
//        List<JwtHsAlgorithm> algs = List.of(Jwt.HS256, Jwt.HS384, Jwt.HS512);
//        Map<String, JwtAlgorithm> algMap = algs.stream().collect(HashMap::new, (m, a) -> m.put(a.getAlgorithmFullName(), a), HashMap::putAll);
//        HashMap<String, JwtKey> keys = new HashMap<String, JwtKey>();
//        ArrayList<String> jwts = new ArrayList<String>();
//
//        for (int i = 0 ; i < 30 ; i++) {
//            JwtHsAlgorithm alg = algs.get((int)(Math.random() * 3));
//            String kid = UUID.randomUUID().toString();
//            JwtKey key = alg.newRandomJwtKey();
//            keys.put(kid, key);
//            jwts.add(Assertions.assertDoesNotThrow(() -> Jwt.builder().kid(kid).id("abc").expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key)));
//        }
//
//        jwts.parallelStream().map(jwt -> Assertions.assertDoesNotThrow(() ->
//                Jwt.parse(jwt, node -> {
//                    JwtAlgorithm alg = algMap.get(node.getAlgorithm());
//                    JwtKey key = keys.get(node.getKid());
//                    return alg.with(key);
//                })
//        )).forEach(JwtNode -> Assertions.assertEquals("abc", JwtNode.getId()));
//        System.out.println("done");
//    }
//}
