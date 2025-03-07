package me.saro.jwt.java.core;

import me.saro.jwt.alg.es.JwtEs256Algorithm;
import me.saro.jwt.Jwt;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.core.JwtNode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

@DisplayName("[Java] example")
public class Example {

    JwtEs256Algorithm alg = Jwt.ES256;

    @Test
    @DisplayName("basic")
    public void t1() {
        JwtKey key = alg.newRandomJwtKey();

        JwtNode.Builder jwtNode = Jwt.builder()
            .issuedAt(OffsetDateTime.now())
            .notBefore(OffsetDateTime.now().minusMinutes(1))
            .expire(OffsetDateTime.now().plusMinutes(30))
            .id("jti value")
            .issuer("iss value")
            .subject("sub value")
            .audience("aud value")
            .claim("custom", "custom value");

        System.out.println(jwtNode);

        String jwt = Assertions.assertDoesNotThrow(() -> jwtNode.toJwt(alg, key));

        System.out.println(jwt);

        JwtNode readJwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));

        System.out.println(readJwtNode);

        Assertions.assertEquals("jti value", readJwtNode.getId());
        Assertions.assertEquals("iss value", readJwtNode.getIssuer());
        Assertions.assertEquals("sub value", readJwtNode.getSubject());
        Assertions.assertEquals("aud value", readJwtNode.getAudience());
        Assertions.assertEquals("custom value", readJwtNode.claim("custom"));
    }

    @Test
    @DisplayName("dynamic key")
    public void t2() {
        HashMap<String, JwtKey> keyMap = new HashMap<String, JwtKey>();
        ArrayList<String> jwtList = new ArrayList<String>();

        // make keys
        for (int i = 0 ; i < 30 ; i++) {
            String kid = UUID.randomUUID().toString();
            JwtKey key = alg.newRandomJwtKey();
            keyMap.put(kid, key);
        }

        // make jwt list with random key
        for (int i = 0 ; i < 10 ; i++) {
            JwtNode.Builder jwtNode = Jwt.builder()
                .issuedAt(OffsetDateTime.now())
                .notBefore(OffsetDateTime.now().minusMinutes(1))
                .expire(OffsetDateTime.now().plusMinutes(30))
                .id("jti value " + i)
                .issuer("iss value " + i)
                .subject("sub value " + i)
                .audience("aud value " + i)
                .claim("custom", "custom value " + i);

            String randomKid = (String)keyMap.keySet().toArray()[(int)(Math.random() * keyMap.size())];
            JwtKey randomKey = keyMap.get(randomKid);

            // make jwt with key / kid(header)
            String jwt = Assertions.assertDoesNotThrow(() -> jwtNode.kid(randomKid).toJwt(alg, randomKey));
            jwtList.add(jwt);
        }

        // decode
        for (int i = 0 ; i < 10 ; i++) {
            String jwt = jwtList.get(i);

            System.out.println();
            System.out.println("jwt : " + jwt);

            JwtNode readJwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(keyMap.get(node.getKid()))));

            Assertions.assertEquals(readJwtNode.getId(), "jti value " + i);
            Assertions.assertEquals(readJwtNode.getIssuer(), "iss value " + i);
            Assertions.assertEquals(readJwtNode.getSubject(), "sub value " + i);
            Assertions.assertEquals(readJwtNode.getAudience(), "aud value " + i);
            Assertions.assertEquals(readJwtNode.claim("custom"), "custom value " + i);
        }
    }
}
