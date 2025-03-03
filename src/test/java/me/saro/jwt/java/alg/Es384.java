package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs384;
import me.saro.jwt.core.Jwt;
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

@DisplayName("[Java] ES384")
public class Es384 {

    JwtEs384 alg = Jwt.es384();

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var jwt = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj";
        var publicKey = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii1D3jaW6pmGVJFhodzC31cy5sfOYotrzF";
        var privateKey = "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=";

        var key = alg.toJwtKey(publicKey, privateKey);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(key)));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> Jwt.parse(jwt, node -> alg.with(alg.newRandomJwtKey())));
        System.out.println("example jwt error text - pass");
    }

    @Test
    @DisplayName("kid test")
    public void t2() {

        var keys = new HashMap<String, JwtKey>();
        var jwtList = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey();
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
            var jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> alg.with(keys.get(node.getKid()))));
            Assertions.assertEquals("abc", jwtNode.getId());
        });
        System.out.println("done");
    }

    @Test
    @DisplayName("expire test")
    public void t3() {
        var key = alg.newRandomJwtKey();

        var jwtPass = Jwt.builder().expire(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));

        var jwtFail = Jwt.builder().expire(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
    }

    @Test
    @DisplayName("not before test")
    public void t4() {
        var key = alg.newRandomJwtKey();

        var jwtPass = Jwt.builder().notBefore(OffsetDateTime.now().minusMinutes(30)).toJwt(alg, key);
        Assertions.assertDoesNotThrow(() -> Jwt.parse(jwtPass, node -> alg.with(key)));

        var jwtFail = Jwt.builder().notBefore(OffsetDateTime.now().plusMinutes(30)).toJwt(alg, key);
        Assertions.assertThrowsExactly(JwtException.class, () -> Jwt.parse(jwtFail, node -> alg.with(key)));
    }

    @Test
    @DisplayName("data test")
    public void t5() {

        var key = alg.newRandomJwtKey();

        var jwt = Jwt.builder()
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
