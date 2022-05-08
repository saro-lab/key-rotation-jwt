//package me.saro.jwt.java.alg;
//
//import me.saro.jwt.alg.es.JwtEs256;
//import me.saro.jwt.alg.hs.JwtHs256;
//import me.saro.jwt.core.JwtKey;
//import me.saro.jwt.exception.JwtException;
//import org.junit.jupiter.api.Assertions;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//
//import java.time.OffsetDateTime;
//import java.util.ArrayList;
//import java.util.concurrent.ConcurrentHashMap;
//
//@DisplayName("[Java] ES256")
//public class ES256 {
//    @Test
//    @DisplayName("check jwt.io example")
//    public void t1() {
//        var exJwtBody = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
//        var exJwtSign = "tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
//        var publicKey = (
//                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9" +
//                "q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg=="
//        );
//        var privateKey = (
//                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2" +
//                "OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r" +
//                "1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G"
//        );
//
//        var alg = new JwtEs256();
//        var key = alg.parseJwtKey(publicKey + " " + privateKey);
//
//        var newJwtSign = alg.signature(exJwtBody, key);
//
//        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
//        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));
//
//        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
//        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
//    }
//
//    @Test
//    @DisplayName("normal")
//    public void t2() {
//        var alg = new JwtEs256();
//        var key1 = alg.randomJwtKey();
//        var key2 = alg.randomJwtKey();
//        var key3 = alg.parseJwtKey(key1.stringify());
//
//        System.out.println("key1: " + key1);
//        System.out.println("key2: " + key2);
//        System.out.println("key3: " + key3);
//
//        var jwtObject = alg.createJwtObject();
//        jwtObject.audience("test aud");
//        jwtObject.id("id test");
//
//        System.out.println("jwtObject: " + jwtObject);
//
//        var jwt1 = alg.toJwt(jwtObject, key1);
//        var jwt2 = alg.toJwt(jwtObject, key2);
//        var jwt3 = alg.toJwt(jwtObject, key3);
//
//        System.out.println("jwt key1: " + jwt1);
//        System.out.println("jwt key2: " + jwt2);
//        System.out.println("jwt key3: " + jwt3);
//
//        Assertions.assertNotEquals(jwt1, jwt2);
//
//        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt1, key1));
//        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt2, key2));
//        Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(jwt3, key3));
//
//        Assertions.assertThrows(JwtException.class, () -> alg.toJwtObjectWithVerify(jwt2, key1));
//    }
//
//    @Test
//    @DisplayName("key store")
//    public void t3() {
//        var alg = new JwtEs256();
//
//        var keyStore = new ConcurrentHashMap<String, JwtKey>();
//        var jwtList = new ArrayList<String>();
//
//        for (var i = 0 ; i < 10 ; i++) {
//            var kid = Integer.toString(i);
//            var key = alg.randomJwtKey();
//            keyStore.put(kid, key);
//            System.out.println("create jwt key : kid["+kid+"] : " + key);
//
//            var jwtObject = alg.createJwtObject();
//            jwtObject.kid(kid);
//            jwtObject.id("test id");
//            System.out.println(jwtObject);
//
//            var jwt = alg.toJwt(jwtObject, key);
//            System.out.println(jwt);
//
//            jwtList.add(jwt);
//        }
//
//        for (var i = 0 ; i < jwtList.size() ; i++) {
//            var jwtObject = alg.toJwtObjectWithVerifyOrNull(jwtList.get(i), kid -> keyStore.get(kid));
//            Assertions.assertNotNull(jwtObject);
//            System.out.println("pass: " + jwtObject);
//        }
//
//        var wrongKeyStore = new ConcurrentHashMap<String, JwtKey>();
//        wrongKeyStore.put("1", new JwtHs256().randomJwtKey());
//        for (var i = 0 ; i < jwtList.size() ; i++) {
//            var jwtObject = alg.toJwtObjectWithVerifyOrNull(jwtList.get(i), kid -> wrongKeyStore.get(kid));
//            Assertions.assertNull(jwtObject);
//            System.out.println("wrong: " + jwtList.get(i));
//        }
//
//    }
//
//    @Test
//    @DisplayName("expire")
//    public void t4() {
//        var alg = new JwtEs256();
//
//        var key = alg.randomJwtKey();
//        System.out.println(key);
//
//        var validJwtObject = alg.createJwtObject();
//        validJwtObject.expire(OffsetDateTime.now().plusDays(1));
//        System.out.println(validJwtObject);
//        var validJwt = alg.toJwt(validJwtObject, key);
//        System.out.println(validJwt);
//        Assertions.assertTrue(alg.verify(validJwt, key));
//
//        var expireJwtObject = alg.createJwtObject();
//        expireJwtObject.expire(OffsetDateTime.now().minusDays(1));
//        System.out.println(expireJwtObject);
//        var expireJwt = alg.toJwt(expireJwtObject, key);
//        System.out.println(expireJwt);
//        Assertions.assertFalse(alg.verify(expireJwt, key));
//    }
//}
