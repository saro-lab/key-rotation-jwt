package me.saro.jwt.java.alg;

import me.saro.jwt.alg.hs.JwtHs384;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] HS384")
public class HS384 {
    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var alg = new JwtHs384();

        var jwt = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh";
        var secret = "your-384-bit-secret";
        var key = alg.toJwtKey(secret);

        System.out.println("example");
        Assertions.assertDoesNotThrow(() -> alg.toJwtClaims(jwt, key));
        System.out.println("example jwt toJwt - pass");

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtClaims(jwt, alg.toJwtKey("is not key")));
        System.out.println("example jwt error text - pass");
    }
}
