package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs256;
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

@DisplayName("[Java] ES256")
public class Es256 {

    JwtEs256 alg = Jwt.es256();

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        var publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==";
        var privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";

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
            System.out.println(jwt);
            var jwtNode = Assertions.assertDoesNotThrow(() -> Jwt.parse(jwt, node -> {
                var kid = node.getKid();
                System.out.println(kid);
                System.out.println(keys.get(kid));
                return alg.with(keys.get(node.getKid()));
            }));
            //Assertions.assertEquals("abc", jwtNode.getId());
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
