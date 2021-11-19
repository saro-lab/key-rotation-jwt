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
        var exJwtBody = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJpYXQiOjE2MzcyNTk0NDEsImV4cCI6MTYzNzM0NTg0MX0";
        var exJwtSign = "OgkRovv9QLVtPTwdZgkobRNK0cbqqVi_-XELviEAceYzSDYjcHpzC9YA5GOEyKtL";
        var secret = "your-256-bit-secret";

        var alg = new JwtHs384();
        var key = alg.getJwtKey(secret);

        var newJwtSign = alg.signature(exJwtBody, key);

        Assertions.assertEquals(exJwtSign, newJwtSign);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
    }
}
