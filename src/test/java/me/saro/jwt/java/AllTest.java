package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtKey;
import me.saro.jwt.JwtNode;
import me.saro.jwt.JwtUtils;
import me.saro.jwt.exception.JwtException;
import me.saro.jwt.exception.JwtExceptionCode;
import org.junit.jupiter.api.*;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@DisplayName("[Java] all test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName.class)
public class AllTest {

    Map<String, JwtKey> createKeyMap = new HashMap<>();
    Map<String, String> stringKeyMap = new HashMap<>();
    Map<String, JwtKey> convertKeyMap = new HashMap<>();

    @Test
    @DisplayName("[Java] 01 created Keys")
    public void test01() {
        long start = System.currentTimeMillis();

        // HS Algorithm
        createKeyMap.put("HS256_1", Jwt.HS256.newRandomJwtKey());
        createKeyMap.put("HS256_2", Jwt.HS256.newRandomJwtKey(20));
        createKeyMap.put("HS256_3", Jwt.HS256.newRandomJwtKey(10, 40));
        createKeyMap.put("HS256_4", Jwt.HS256.toJwtKey("HS256_4_key"));
        createKeyMap.put("HS256_5", Jwt.HS256.toJwtKeyByBase64Url(JwtUtils.encodeBase64UrlString("HS256_4_key")));
        createKeyMap.put("HS384_1", Jwt.HS384.newRandomJwtKey());
        createKeyMap.put("HS384_2", Jwt.HS384.newRandomJwtKey(20));
        createKeyMap.put("HS384_3", Jwt.HS384.newRandomJwtKey(10, 40));
        createKeyMap.put("HS384_4", Jwt.HS384.toJwtKey("HS384_4_key"));
        createKeyMap.put("HS384_5", Jwt.HS384.toJwtKeyByBase64Url(JwtUtils.encodeBase64UrlString("HS384_4_key")));
        createKeyMap.put("HS512_1", Jwt.HS512.newRandomJwtKey());
        createKeyMap.put("HS512_2", Jwt.HS512.newRandomJwtKey(20));
        createKeyMap.put("HS512_3", Jwt.HS512.newRandomJwtKey(10, 40));
        createKeyMap.put("HS512_4", Jwt.HS512.toJwtKey("HS512_4_key"));
        createKeyMap.put("HS512_5", Jwt.HS512.toJwtKeyByBase64Url(JwtUtils.encodeBase64UrlString("HS512_4_key")));

        // ES Algorithm
        createKeyMap.put("ES256_1", Jwt.ES256.newRandomJwtKey());
        createKeyMap.put("ES256_2", Jwt.ES256.newRandomJwtKey());
        createKeyMap.put("ES256_3", Jwt.ES256.newRandomJwtKey());
        createKeyMap.put("ES384_1", Jwt.ES384.newRandomJwtKey());
        createKeyMap.put("ES384_2", Jwt.ES384.newRandomJwtKey());
        createKeyMap.put("ES384_3", Jwt.ES384.newRandomJwtKey());
        createKeyMap.put("ES512_1", Jwt.ES512.newRandomJwtKey());
        createKeyMap.put("ES512_2", Jwt.ES512.newRandomJwtKey());
        createKeyMap.put("ES512_3", Jwt.ES512.newRandomJwtKey());

        // PS Algorithm
        createKeyMap.put("PS256_1", Jwt.PS256.newRandomJwtKey());
        createKeyMap.put("PS256_2", Jwt.PS256.newRandomJwtKey(2048));
        createKeyMap.put("PS256_3", Jwt.PS256.newRandomJwtKey(3072));
        createKeyMap.put("PS256_4", Jwt.PS256.newRandomJwtKey(4096));
        createKeyMap.put("PS384_1", Jwt.PS384.newRandomJwtKey());
        createKeyMap.put("PS384_2", Jwt.PS384.newRandomJwtKey(2048));
        createKeyMap.put("PS384_3", Jwt.PS384.newRandomJwtKey(3072));
        createKeyMap.put("PS384_4", Jwt.PS384.newRandomJwtKey(4096));
        createKeyMap.put("PS512_1", Jwt.PS512.newRandomJwtKey());
        createKeyMap.put("PS512_2", Jwt.PS512.newRandomJwtKey(2048));
        createKeyMap.put("PS512_3", Jwt.PS512.newRandomJwtKey(3072));
        createKeyMap.put("PS512_4", Jwt.PS512.newRandomJwtKey(4096));

        // RS Algorithm
        createKeyMap.put("RS256_1", Jwt.RS256.newRandomJwtKey());
        createKeyMap.put("RS256_2", Jwt.RS256.newRandomJwtKey(2048));
        createKeyMap.put("RS256_3", Jwt.RS256.newRandomJwtKey(3072));
        createKeyMap.put("RS256_4", Jwt.RS256.newRandomJwtKey(4096));
        createKeyMap.put("RS384_1", Jwt.RS384.newRandomJwtKey());
        createKeyMap.put("RS384_2", Jwt.RS384.newRandomJwtKey(2048));
        createKeyMap.put("RS384_3", Jwt.RS384.newRandomJwtKey(3072));
        createKeyMap.put("RS384_4", Jwt.RS384.newRandomJwtKey(4096));
        createKeyMap.put("RS512_1", Jwt.RS512.newRandomJwtKey());
        createKeyMap.put("RS512_2", Jwt.RS512.newRandomJwtKey(2048));
        createKeyMap.put("RS512_3", Jwt.RS512.newRandomJwtKey(3072));
        createKeyMap.put("RS512_4", Jwt.RS512.newRandomJwtKey(4096));

        Assertions.assertEquals(48, createKeyMap.size());
        System.out.println("create " + createKeyMap.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 02 stringify keys")
    public void test02() {
        Assertions.assertNotEquals(0, createKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        createKeyMap.forEach((kid, key) -> stringKeyMap.put(kid, key.getStringify()) );

        Assertions.assertEquals(48, stringKeyMap.size());

        stringKeyMap.forEach((kid, key) -> System.out.println(kid + " : " + key));
        System.out.println("pass stringify " + stringKeyMap.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 03 convert string keys")
    public void test03() {
        Assertions.assertNotEquals(0, stringKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        stringKeyMap.forEach((kid, key) -> convertKeyMap.put(kid, Jwt.parseKey(key)));

        Assertions.assertEquals(48, convertKeyMap.size());

        System.out.println("pass convert " + convertKeyMap.size() + " keys - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 04 expired")
    public void test04() {
        Assertions.assertNotEquals(0, createKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        createKeyMap.forEach((kid, key) -> {
            String jwt = key.createJwt()
                    .kid(kid)
                    .expire(OffsetDateTime.now().minusMinutes(1))
                    .toJwt();
            JwtException exception = Assertions.assertThrows(JwtException.class, () -> Jwt.parseJwt(jwt, node -> convertKeyMap.get(node.getKid())));
            Assertions.assertEquals(JwtExceptionCode.DATE_EXPIRED, exception.getCode());
        });
        stringKeyMap.forEach((kid, key) -> convertKeyMap.put(kid, Jwt.parseKey(key)));

        System.out.println("pass expired test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 05 not before")
    public void test05() {
        Assertions.assertNotEquals(0, createKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        createKeyMap.forEach((kid, key) -> {
            String jwt = key.createJwt()
                    .kid(kid)
                    .notBefore(OffsetDateTime.now().plusDays(1))
                    .toJwt();
            JwtException exception = Assertions.assertThrows(JwtException.class, () -> Jwt.parseJwt(jwt, node -> convertKeyMap.get(node.getKid())));
            Assertions.assertEquals(JwtExceptionCode.DATE_BEFORE, exception.getCode());
        });
        stringKeyMap.forEach((kid, key) -> convertKeyMap.put(kid, Jwt.parseKey(key)));

        System.out.println("pass not before test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 06 pass")
    public void test06() {
        Assertions.assertNotEquals(0, createKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        createKeyMap.forEach((kid, key) -> {
            String jwt = key.createJwt()
                    .kid(kid)
                    .toJwt();
            JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, it -> convertKeyMap.get(it.getKid())));
            Assertions.assertEquals(kid, node.getKid());
        });

        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
    }

    @Test
    @DisplayName("[Java] 07 data")
    public void test07() {
        Assertions.assertNotEquals(0, createKeyMap.size(), "This function cannot be tested independently. Please run the entire test.");

        long start = System.currentTimeMillis();

        String issuer = "issuer1";
        String subject = "subject2";
        String audience = "audience3";
        String id = "id4";
        var boolData = true;
        var boolData2 = "no";
        var boolData3 = "1";
        var boolData4 = "Y";
        var boolData5 = "YeS";
        var boolData6 = "N";
        var intData1 = 1237890;
        var intData2 = "-7890";
        var longData1 = 1234567891110L;
        var longData2 = "42345678911103";
        Date issuedAt = new Date(OffsetDateTime.now().toEpochSecond() * 1000L);
        long notBefore = OffsetDateTime.now().minusMinutes(1).toEpochSecond();
        long expire = OffsetDateTime.now().plusHours(1).toEpochSecond();

        createKeyMap.forEach((kid, key) -> {
            String jwt = key.createJwt()
                    .kid(kid)
                    .issuer(issuer)
                    .subject(subject)
                    .audience(audience)
                    .id(id)
                    .claim("boolData", boolData)
                    .claim("boolData2", boolData2)
                    .claim("boolData3", boolData3)
                    .claim("boolData4", boolData4)
                    .claim("boolData5", boolData5)
                    .claim("boolData6", boolData6)
                    .claim("intData1", intData1)
                    .claim("intData2", intData2)
                    .claim("longData1", longData1)
                    .claim("longData2", longData2)
                    .claim("test", "test-value")
                    .issuedAt(issuedAt)
                    .notBefore(notBefore)
                    .expire(expire)
                    .toJwt();
            JwtNode node = Assertions.assertDoesNotThrow(() -> Jwt.parseJwt(jwt, it -> convertKeyMap.get(it.getKid())));
            Assertions.assertEquals(kid, node.getKid());
            Assertions.assertEquals(key.getAlgorithm().getAlgorithmFullName(), node.getAlgorithm());
            Assertions.assertEquals(issuer, node.getIssuer());
            Assertions.assertEquals(subject, node.getSubject());
            Assertions.assertEquals(audience, node.getAudience());
            Assertions.assertEquals(id, node.getId());
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"));
            Assertions.assertEquals(false, node.claimBoolean("boolData2"));
            Assertions.assertEquals(true, node.claimBoolean("boolData3"));
            Assertions.assertEquals(true, node.claimBoolean("boolData4"));
            Assertions.assertEquals(true, node.claimBoolean("boolData5"));
            Assertions.assertEquals(false, node.claimBoolean("boolData6"));
            Assertions.assertEquals(intData1, node.claimInt("intData1"));
            Assertions.assertEquals(-7890, node.claimInt("intData2"));
            Assertions.assertEquals(longData1, node.claimLong("longData1"));
            Assertions.assertEquals(42345678911103L, node.claimLong("longData2"));
            Assertions.assertEquals("test-value", node.claimString("test"));
            Assertions.assertEquals(issuedAt, node.getIssuedAt());
            Assertions.assertEquals(notBefore, node.getNotBeforeEpochSecond());
            Assertions.assertEquals(expire, node.getExpireEpochSecond());
            System.out.println("pass: " + node);
        });

        System.out.println("pass test - " + (System.currentTimeMillis() - start) + "ms");
    }

}
