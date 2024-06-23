package me.saro.jwt.java.alg;

import me.saro.jwt.alg.hs.JwtHs;
import me.saro.jwt.core.Jwt;
import me.saro.jwt.core.JwtClaims;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@DisplayName("[Java] HS Thread And Random KID Test")
public class HsThreadTest {
    @Test
    @DisplayName("Thread And Random KID Test")
    public void t1() {
        var algs = List.of(Jwt.hs256(), Jwt.hs384(), Jwt.hs512());
        var keys = new HashMap<String, JwtKey>();
        var jwts = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            var alg = algs.get((int)(Math.random() * 3));
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey();
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
            JwtHs _alg = null;
            switch (jh.getAlgorithm()) {
                case "HS256": _alg = Jwt.hs256(); break;
                case "HS384": _alg = Jwt.hs384(); break;
                case "HS512": _alg = Jwt.hs512(); break;
            }
            var alg = _alg;
            Assertions.assertNotNull(alg);

            var key = keys.get(jh.getKid());
            Assertions.assertNotNull(key);

            var jc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
            Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey()));

            Assertions.assertEquals(jc.getId(), "abc");
        });
        System.out.println("done");
    }
}
