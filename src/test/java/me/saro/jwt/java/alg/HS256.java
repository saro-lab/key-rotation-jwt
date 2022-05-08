package me.saro.jwt.java.alg;

import me.saro.jwt.alg.hs.JwtHs256;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] HS256")
public class HS256 {
    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var alg = new JwtHs256();

        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        var secret = "your-256-bit-secret";
        var key = alg.getJwtKey(secret);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.getJwtKey("is not key")));
        System.out.println("example jwt error text - pass");
    }
}
