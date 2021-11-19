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
        var exJwtBody = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        var exJwtSign = "ypNASjsXTW6nmFdRxHAw-7s7tLMLj_jKknIXprDZkSs";
        var secret = "your-secret-key";

        var alg = new JwtHs256();
        var key = alg.getJwtKey(secret);

        var newJwtSign = alg.signature(exJwtBody, key);

        Assertions.assertEquals(exJwtSign, newJwtSign);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));

        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
    }
}
