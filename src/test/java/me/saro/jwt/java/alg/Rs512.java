package me.saro.jwt.java.alg;

import me.saro.jwt.alg.rs.JwtRs512;
import me.saro.jwt.core.Jwt;
import me.saro.jwt.core.JwtClaims;
import me.saro.jwt.core.JwtKey;
import me.saro.jwt.exception.JwtException;
import me.saro.jwt.exception.JwtExceptionCode;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

@DisplayName("[Java] RS512")
public class Rs512 {

    public JwtRs512 alg() {
        return Jwt.rs512();
    }

    public int randomKeyBit() {
        return List.of(2048, 3072, 4096).get((int)(Math.random() * 3));
    }

    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var jwt = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.jYW04zLDHfR1v7xdrW3lCGZrMIsVe0vWCfVkN2DRns2c3MN-mcp_-RE6TN9umSBYoNV-mnb31wFf8iun3fB6aDS6m_OXAiURVEKrPFNGlR38JSHUtsFzqTOj-wFrJZN4RwvZnNGSMvK3wzzUriZqmiNLsG8lktlEn6KA4kYVaM61_NpmPHWAjGExWv7cjHYupcjMSmR8uMTwN5UuAwgW6FRstCJEfoxwb0WKiyoaSlDuIiHZJ0cyGhhEmmAPiCwtPAwGeaL1yZMcp0p82cpTQ5Qb-7CtRov3N4DcOHgWYk6LomPR5j5cCkePAz87duqyzSMpCB0mCOuE3CU2VMtGeQ";
        var publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n" +
                "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n" +
                "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n" +
                "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n" +
                "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n" +
                "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n" +
                "mwIDAQAB\n" +
                "-----END PUBLIC KEY-----";
        var privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj\n" +
                "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n" +
                "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n" +
                "qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg\n" +
                "p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR\n" +
                "ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi\n" +
                "VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV\n" +
                "laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8\n" +
                "sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H\n" +
                "mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY\n" +
                "dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw\n" +
                "ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ\n" +
                "DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T\n" +
                "N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t\n" +
                "0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv\n" +
                "t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU\n" +
                "AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk\n" +
                "48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL\n" +
                "DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK\n" +
                "xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA\n" +
                "mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh\n" +
                "2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz\n" +
                "et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr\n" +
                "VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD\n" +
                "TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc\n" +
                "dn/RsYEONbwQSjIfMPkvxF+8HQ==\n" +
                "-----END PRIVATE KEY-----";

        var alg = alg();
        var key = alg.toJwtKey(publicKey, privateKey);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey(randomKeyBit())));
        System.out.println("example jwt error text - pass");
    }

    @Test
    @DisplayName("kid test")
    public void t2() {
        var alg = alg();
        var keys = new HashMap<String, JwtKey>();
        var jwtList = new ArrayList<String>();

        for (int i = 0 ; i < 30 ; i++) {
            var kid = UUID.randomUUID().toString();
            var key = alg.newRandomJwtKey(randomKeyBit());
            keys.put(kid, key);

            var jc = JwtClaims.create();
            jc.id("abc");
            jc.expire(OffsetDateTime.now().plusMinutes(30));

            jwtList.add(Assertions.assertDoesNotThrow(() -> alg.toJwt(key, jc, kid)));
        }

        jwtList.parallelStream().forEach(jwt -> {
            var jh = alg.toJwtHeader(jwt);

            var key = keys.get(jh.getKid());
            Assertions.assertNotNull(key);

            var jc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
            Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.newRandomJwtKey(randomKeyBit())));

            Assertions.assertEquals(jc.getId(), "abc");
        });
        System.out.println("done");
    }

    @Test
    @DisplayName("expire test")
    public void t3() {
        var alg = alg();
        var key = alg.newRandomJwtKey(randomKeyBit());

        var jcp = JwtClaims.create();
        jcp.expire(OffsetDateTime.now().plusMinutes(30));
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(alg.toJwt(key, jcp), key));

        var jce = JwtClaims.create();
        jce.expire(OffsetDateTime.now().minusMinutes(30));
        Assertions.assertThrowsExactly(JwtException.class, () -> alg.toJwtClaims(alg.toJwt(key, jce), key), JwtExceptionCode.DATE_EXPIRED.name());
    }

    @Test
    @DisplayName("not before test")
    public void t4() {
        var alg = alg();
        var key = alg.newRandomJwtKey(randomKeyBit());

        var jcp = JwtClaims.create();
        jcp.notBefore(OffsetDateTime.now().minusMinutes(30));
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(alg.toJwt(key, jcp), key));

        var jce = JwtClaims.create();
        jce.notBefore(OffsetDateTime.now().plusMinutes(30));
        Assertions.assertThrowsExactly(JwtException.class, () -> alg.toJwtClaims(alg.toJwt(key, jce), key), JwtExceptionCode.DATE_EXPIRED.name());
    }

    @Test
    @DisplayName("data test")
    public void t5() {
        var alg = alg();
        var key = alg.newRandomJwtKey(randomKeyBit());

        var jc = JwtClaims.create();
        jc.issuedAt(OffsetDateTime.now());
        jc.notBefore(OffsetDateTime.now().minusMinutes(1));
        jc.expire(OffsetDateTime.now().plusMinutes(30));
        jc.id("jti value");
        jc.issuer("iss value");
        jc.subject("sub value");
        jc.audience("aud value");
        jc.claim("custom", "custom value");

        System.out.println(jc);

        var jwt = alg.toJwt(key, jc);

        System.out.println(jwt);

        var njc = Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));

        System.out.println(njc);

        Assertions.assertEquals(njc.getId(), "jti value");
        Assertions.assertEquals(njc.getIssuer(), "iss value");
        Assertions.assertEquals(njc.getSubject(), "sub value");
        Assertions.assertEquals(njc.getAudience(), "aud value");
        Assertions.assertEquals(njc.claim("custom"), "custom value");
    }
}
