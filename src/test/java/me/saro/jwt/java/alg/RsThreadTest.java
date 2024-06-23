package me.saro.jwt.java.alg;

import me.saro.jwt.core.*;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@DisplayName("[Java] RS Thread And Random KID Test")
public class RsThreadTest {

    public int randomKeyBit() {
        return List.of(2048, 3072, 4096).get((int)(Math.random() * 3));
    }

    @Test
    @DisplayName("Thread And Random KID Test")
    public void t1() {
        var algs = List.of(Jwt.rs256(), Jwt.rs384(), Jwt.rs512());
        var keys = new HashMap<String, JwtKey>();
        var jwts = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            var alg = algs.get((int)(Math.random() * 3));
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey(randomKeyBit());
            keys.put(kid, key);

            var jc = JwtClaims.create();
            jc.id("abc");
            jc.expire(OffsetDateTime.now().plusMinutes(30));

            jwts.add(Assertions.assertDoesNotThrow(() -> alg.toJwt(key, jc, kid)));
        }

        jwts.parallelStream().forEach(jwt -> {
            // use alg.toJwtHeader
            // but this case is unknown alg
            // use JwtUtils.toJwtHeader
            var jh = Jwt.toJwtHeader(jwt);
            JwtAlgorithmPemKeyPair _alg = null;
            switch (jh.getAlgorithm()) {
                case "RS256": _alg = Jwt.rs256(); break;
                case "RS384": _alg = Jwt.rs384(); break;
                case "RS512": _alg = Jwt.rs512(); break;
            }
            var alg = _alg;
            Assertions.assertNotNull(alg);

            var key = keys.get(jh.getKid());
            Assertions.assertNotNull(key);

            var jc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
            Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey(randomKeyBit())));

            Assertions.assertEquals(jc.getId(), "abc");
        });
        System.out.println("done");
    }
}
