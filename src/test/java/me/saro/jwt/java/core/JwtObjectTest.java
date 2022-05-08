//package me.saro.jwt.java.core;
//
//import me.saro.jwt.alg.es.JwtEs256;
//import me.saro.jwt.alg.es.JwtEs384;
//import me.saro.jwt.alg.es.JwtEs512;
//import me.saro.jwt.alg.hs.JwtHs256;
//import me.saro.jwt.alg.hs.JwtHs384;
//import me.saro.jwt.alg.hs.JwtHs512;
//import me.saro.jwt.core.JwtAlgorithm;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//
//import java.text.ParseException;
//import java.text.SimpleDateFormat;
//
//@DisplayName("[Java] JwtObject")
//public class JwtObjectTest {
//    @Test
//    @DisplayName("input / output")
//    public void t1() throws ParseException {
//        jwtObjectTest(new JwtEs256());
//        jwtObjectTest(new JwtEs384());
//        jwtObjectTest(new JwtEs512());
//        jwtObjectTest(new JwtHs256());
//        jwtObjectTest(new JwtHs384());
//        jwtObjectTest(new JwtHs512());
//    }
//
//    private void jwtObjectTest(JwtAlgorithm alg) throws ParseException {
//        var simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
//
//        var jwtObject = alg.createJwtObject();
//        var jwtKey = alg.randomJwtKey();
//
//        jwtObject.header("h1", "v1");
//        jwtObject.header("h2", "v2");
//        jwtObject.header("h3", "v3");
//
//        jwtObject.kid("kid1");
//
//        jwtObject.audience("aud1");
//        jwtObject.id("id2");
//        jwtObject.issuer("iss3");
//        jwtObject.subject("sub4");
//
//        jwtObject.issuedAt(simpleDateFormat.parse("1988-01-01 03:01:32"));
//        jwtObject.notBefore(simpleDateFormat.parse("2000-03-11 03:22:11"));
//        jwtObject.expire(simpleDateFormat.parse("2999-12-31 00:00:00"));
//
//        jwtObject.claim("c1", "v1");
//        jwtObject.claim("c2", "v2");
//        jwtObject.claim("c3", "v3");
//
//        System.out.println(jwtObject);
//        var jwt = alg.toJwt(jwtObject, jwtKey);
//        System.out.println(jwt);
//
//        var jwtObject2 = alg.toJwtObjectWithVerifyOrNull(jwt, jwtKey);
//        System.out.println(jwtObject2);
//
//        Assertions.assertEquals(jwtObject2.header("h1"), "v1");
//        Assertions.assertEquals(jwtObject2.header("h2"), "v2");
//        Assertions.assertEquals(jwtObject2.header("h3"), "v3");
//
//        Assertions.assertEquals(jwtObject2.kid(), "kid1");
//
//        Assertions.assertEquals(jwtObject2.audience(), "aud1");
//        Assertions.assertEquals(jwtObject2.id(), "id2");
//        Assertions.assertEquals(jwtObject2.issuer(), "iss3");
//        Assertions.assertEquals(jwtObject2.subject(), "sub4");
//
//        Assertions.assertEquals(jwtObject2.issuedAt(), simpleDateFormat.parse("1988-01-01 03:01:32"));
//        Assertions.assertEquals(jwtObject2.notBefore(), simpleDateFormat.parse("2000-03-11 03:22:11"));
//        Assertions.assertEquals(jwtObject2.expire(), simpleDateFormat.parse("2999-12-31 00:00:00"));
//
//        Assertions.assertEquals(jwtObject2.claim("c1"), "v1");
//        Assertions.assertEquals(jwtObject2.claim("c2"), "v2");
//        Assertions.assertEquals(jwtObject2.claim("c3"), "v3");
//    }
//}
