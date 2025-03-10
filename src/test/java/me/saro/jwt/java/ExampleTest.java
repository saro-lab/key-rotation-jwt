package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtNode;
import org.junit.jupiter.api.*;

import java.time.OffsetDateTime;

@DisplayName("[Java] example test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName.class)
public class ExampleTest {

    @Test
    @DisplayName("[Java] 01 single key test")
    public void test01SingleKey() {
        System.out.println("For an applied usage example, please refer to AllTest");

        var es256 = Jwt.ES256;
        var key = es256.newRandomJwtKey();

        String issuer = "issuer1";
        String subject = "subject2";
        String audience = "audience3";
        String id = "id4";
        var boolData = true;
        var boolData2 = "no";
        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();

        // create jwt
        String jwt = Jwt.createJwt(key)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .expire(expire)
                .toJwt();

        System.out.println("jwt: " + jwt);

        // parse jwt
        JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, it -> key));
        Assertions.assertEquals(key.getAlgorithm().getAlgorithmFullName(), node.getAlgorithm());
        Assertions.assertEquals(issuer, node.getIssuer());
        Assertions.assertEquals(subject, node.getSubject());
        Assertions.assertEquals(audience, node.getAudience());
        Assertions.assertEquals(id, node.getId());
        Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
        Assertions.assertEquals(false, node.claimBoolean("boolData2"));
        Assertions.assertEquals(expire, node.getExpireEpochSecond());

        System.out.println("jwt node: " + node);
    }

    @Test
    @DisplayName("[Java] 02 key store test")
    public void test02KeyStore() {

    }


}
