package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtAlgorithm;
import me.saro.jwt.JwtKey;
import me.saro.jwt.JwtNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@DisplayName("[Java] Key ID test")
public class KeyIdTest {

    @Test
    @DisplayName("[Java] Key ID test")
    public void kid() {
        // create string key list
        Map<String, String> stringKeyMap = createKeyId(3, Jwt.ES256, Jwt.ES384, Jwt.ES512, Jwt.HS256, Jwt.HS384, Jwt.HS512, Jwt.PS256, Jwt.PS384, Jwt.PS512, Jwt.RS256, Jwt.RS384, Jwt.RS512);
        // convert string key list to key list
        Map<String, JwtKey> keyMap = convertKeyId(stringKeyMap);

        // create jwts
        long start = System.currentTimeMillis();
        List<String> jwtList = new ArrayList<>();
        keyMap.forEach((kid, key) -> {
            for (int i = 0 ; i < 10 ; i++) {
                String jwt = key.newJwtBuilder()
                        .kid(kid)
                        .subject("1234567890")
                        .claim("name", "John Doe")
                        .claim("admin", true)
                        .claim("iat", 1516239022)
                        .toJwt();
                jwtList.add(jwt);
            }
        });
        System.out.println("create " + jwtList.size() + " jwts - " + (System.currentTimeMillis() - start) + "ms");

        // parse jwts
        start = System.currentTimeMillis();
        for (String jwt : jwtList) {
            JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, e -> keyMap.get(e.getKid())));
            Assertions.assertEquals("1234567890", node.getSubject());
            Assertions.assertEquals("John Doe", node.claimString("name"));
            Assertions.assertEquals(true, node.claimBoolean("admin"));
            Assertions.assertEquals(1516239022, node.claimInt("iat"));
        }
        System.out.println("parse " + jwtList.size() + " jwts - " + (System.currentTimeMillis() - start) + "ms");
    }

    public Map<String, String> createKeyId(int loop, JwtAlgorithm... algs) {
        Map<String, String> keyMap = new HashMap<>();
        long start = System.currentTimeMillis();
        long kid = System.currentTimeMillis();
        for (JwtAlgorithm alg : algs) {
            for (int i = 0 ; i < loop ; i++) {
                keyMap.put(Long.toString(kid++), alg.newRandomJwtKey().getStringify());
            }
        }
        keyMap.forEach((k, key) -> {
            System.out.println(k + " : " + key);
        });
        System.out.println("create String keys " + (loop * algs.length) + " keys - " + (System.currentTimeMillis() - start) + "ms");
        return keyMap;
    }

    public Map<String, JwtKey> convertKeyId(Map<String, String> stringJwtKeyMap) {
        Map<String, JwtKey> keyMap = new HashMap<>();
        long start = System.currentTimeMillis();

        stringJwtKeyMap.forEach((kid, key) -> {
            keyMap.put(kid, Jwt.parseKey(key));
        });

        System.out.println("convert " + keyMap.size() + " String keys - " + (System.currentTimeMillis() - start) + "ms");

        return keyMap;
    }
}
