package me.saro.jwt.java.hs;

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

        var newJwtSign = alg.signature(key, exJwtBody);

        Assertions.assertEquals(exJwtSign, newJwtSign);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.verify(key, exJwtBody + "." + exJwtSign)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.verify(key, exJwtBody + "." + newJwtSign)));

        Assertions.assertThrows(JwtException.class, () -> alg.verify(key, exJwtBody + "." + exJwtSign+"1"));
        Assertions.assertThrows(JwtException.class, () -> alg.verify(key, exJwtBody + "." + newJwtSign+"1"));
    }

    @Test
    @DisplayName("normal")
    public void t2() {
        var alg = new JwtHs256();
        var key1 = alg.randomJwtKey();
        var key2 = alg.randomJwtKey();
        var key3 = alg.parseJwtKey(key1.stringify());

        System.out.println("key1: " + key1);
        System.out.println("key2: " + key2);
        System.out.println("key3: " + key3);

        var jwtObject = alg.createJwtObject();
        jwtObject.audience("test aud");
        jwtObject.id("id test");

        System.out.println("jwtObject: " + jwtObject);

        var jwt1 = alg.toJwt(key1, jwtObject);
        var jwt2 = alg.toJwt(key2, jwtObject);
        var jwt3 = alg.toJwt(key3, jwtObject);

        System.out.println("jwt key1: " + jwt1);
        System.out.println("jwt key2: " + jwt2);
        System.out.println("jwt key3: " + jwt3);

        Assertions.assertNotEquals(jwt1, jwt2);
        Assertions.assertEquals(jwt1, jwt3);

        Assertions.assertDoesNotThrow(() -> alg.verify(key1, jwt1));
        Assertions.assertDoesNotThrow(() -> alg.verify(key2, jwt2));
        Assertions.assertDoesNotThrow(() -> alg.verify(key3, jwt3));

        Assertions.assertThrows(JwtException.class, () -> alg.verify(key1, jwt2));
    }


}
