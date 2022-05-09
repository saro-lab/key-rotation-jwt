package me.saro.jwt.java.core;

import me.saro.jwt.alg.es.JwtEs256;
import me.saro.jwt.core.JwtAlgorithm;
import me.saro.jwt.core.JwtClaims;
import me.saro.jwt.core.JwtKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

@DisplayName("[Java] example")
public class Example {

    public JwtAlgorithm alg() {
        return new JwtEs256();
    }

    @Test
    @DisplayName("basic")
    public void t1() {
        var alg = alg();
        var key = alg.newRandomJwtKey();

        var claims = JwtClaims.create();
        claims.issuedAt(OffsetDateTime.now());
        claims.notBefore(OffsetDateTime.now().minusMinutes(1));
        claims.expire(OffsetDateTime.now().plusMinutes(30));
        claims.id("jti value");
        claims.issuer("iss value");
        claims.subject("sub value");
        claims.audience("aud value");
        claims.claim("custom", "custom value");

        System.out.println(claims);

        var jwt = alg.toJwt(key, claims);

        System.out.println(jwt);

        var newClaims = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));

        System.out.println(newClaims);

        Assertions.assertEquals(newClaims.id(), "jti value");
        Assertions.assertEquals(newClaims.issuer(), "iss value");
        Assertions.assertEquals(newClaims.subject(), "sub value");
        Assertions.assertEquals(newClaims.audience(), "aud value");
        Assertions.assertEquals(newClaims.claim("custom"), "custom value");
    }

    @Test
    @DisplayName("dynamic key")
    public void t2() {

        var alg = alg();
        var keyMap = new HashMap<String, JwtKey>();
        var jwtList = new ArrayList<String>();

        // make keys
        for (int i = 0 ; i < 30 ; i++) {
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey();
            keyMap.put(kid, key);
            // key to string (save DB)
            // - key.stringify()
            // string to key (load DB)
            // - alg.toJwtKey(key.stringify())
        }

        // make jwt list with random key
        for (int i = 0 ; i < 10 ; i++) {
            var claims = JwtClaims.create();
            claims.issuedAt(OffsetDateTime.now());
            claims.notBefore(OffsetDateTime.now().minusMinutes(1));
            claims.expire(OffsetDateTime.now().plusMinutes(30));
            claims.id("jti value " + i);
            claims.issuer("iss value " + i);
            claims.subject("sub value " + i);
            claims.audience("aud value " + i);
            claims.claim("custom", "custom value " + i);

            var randomKid = (String)keyMap.keySet().toArray()[(int)(Math.random() * keyMap.size())];
            var randomKey = keyMap.get(randomKid);

            // make jwt with key / kid(header)
            var jwt = alg.toJwt(randomKey, claims, randomKid);
            jwtList.add(jwt);
        }

        // decode
        for (int i = 0 ; i < 10 ; i++) {
            var jwt = jwtList.get(i);
            var header = alg.toJwtHeader(jwt);
            var key = keyMap.get(header.getKid());
            var claims = alg.toJwtClaims(jwt, key);

            System.out.println();
            System.out.println("jwt : " + jwt);
            System.out.println(header);
            System.out.println(claims);

            Assertions.assertEquals(claims.id(), "jti value " + i);
            Assertions.assertEquals(claims.issuer(), "iss value " + i);
            Assertions.assertEquals(claims.subject(), "sub value " + i);
            Assertions.assertEquals(claims.audience(), "aud value " + i);
            Assertions.assertEquals(claims.claim("custom"), "custom value " + i);
        }
    }
}
