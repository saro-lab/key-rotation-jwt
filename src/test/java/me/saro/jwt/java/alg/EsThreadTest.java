package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs;
import me.saro.jwt.core.Jwt;
import me.saro.jwt.core.JwtAlgorithm;
import me.saro.jwt.core.JwtKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.*;

@DisplayName("[Java] ES Thread And Random KID Test")
public class EsThreadTest {
    @Test
    @DisplayName("Thread And Random KID Test")
    public void t1() {
        List<JwtEs> algs = List.of(Jwt.ES256, Jwt.ES384, Jwt.ES512);
        Map<String, JwtAlgorithm> algMap = algs.stream().collect(HashMap::new, (m, a) -> m.put(a.getAlgorithm(), a), HashMap::putAll);
        HashMap<String, JwtKey> keys = new HashMap<String, JwtKey>();
        ArrayList<String> jwts = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            JwtEs alg = algs.get((int)(Math.random() * 3));
            String kid = UUID.randomUUID().toString();
            JwtKey key = alg.newRandomJwtKey();
            keys.put(kid, key);
            jwts.add(Assertions.assertDoesNotThrow(() -> Jwt.builder().kid(kid).id("abc").expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key)));
        }

        jwts.parallelStream().map(jwt -> Assertions.assertDoesNotThrow(() ->
                Jwt.parse(jwt, node -> {
                    JwtAlgorithm alg = algMap.get(node.getAlgorithm());
                    JwtKey key = keys.get(node.getKid());
                    return alg.with(key);
                })
        )).forEach(JwtNode -> Assertions.assertEquals("abc", JwtNode.getId()));
        System.out.println("done");
    }
}
