package me.saro.jwt.java;

import me.saro.jwt.Jwt;
import me.saro.jwt.JwtKey;
import me.saro.jwt.JwtNode;
import me.saro.jwt.exception.JwtException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] jwt.io spec check")
public class SpecTest {

    public JwtNode toJwt(String jwt, JwtKey key) {
        return Jwt.parseJwt(jwt, node -> key);
    }

    public JwtNode toJwt(String jwt, String key) {
        return Jwt.parseJwt(jwt, node -> Jwt.parseKey(node.getAlgorithm() + " " + key));
    }

    @Test
    @DisplayName("HS256 check jwt.io example")
    public void es256() {
        String jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA";
        String publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==";
        String privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G";

        Assertions.assertThrows(JwtException.class, () -> toJwt(jwt, Jwt.ES256.newRandomJwtKey()));
        JwtNode node = Assertions.assertDoesNotThrow(() -> toJwt(jwt, publicKey + " " + privateKey));
    }
}
