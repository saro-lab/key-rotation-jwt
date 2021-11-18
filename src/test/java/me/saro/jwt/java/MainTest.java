package me.saro.jwt.java;

import me.saro.jwt.alg.es.JwtEs384;
import me.saro.jwt.alg.es.JwtEsKey;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] MainTest")
public class MainTest {
    @Test
    @DisplayName("normal")
    public void t1() {
        var es = new JwtEs384();
        var key = (JwtEsKey)es.randomJwtKey();

        var body = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var sig = es.signature(key, body);
        System.out.println(body + "." + sig);
        System.out.println(key.stringify());
    }
}
