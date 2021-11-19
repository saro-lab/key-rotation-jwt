package me.saro.jwt.java.alg;

import me.saro.jwt.alg.hs.JwtHs512;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] HS512")
public class HS512 {
    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var exJwtBody = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var exJwtSign = "VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg";
        var secret = "your-512-bit-secret";

        var alg = new JwtHs512();
        var key = alg.getJwtKey(secret);

        var newJwtSign = alg.signature(exJwtBody, key);

        Assertions.assertEquals(exJwtSign, newJwtSign);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
    }
}
