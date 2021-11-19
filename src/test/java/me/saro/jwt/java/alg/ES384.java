package me.saro.jwt.java.alg;

import me.saro.jwt.alg.es.JwtEs384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("[Java] ES384")
public class ES384 {
    @Test
    @DisplayName("check jwt.io example")
    public void t1() {
        var exJwtBody = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        var exJwtSign = "VUPWQZuClnkFbaEKCsPy7CZVMh5wxbCSpaAWFLpnTe9J0--PzHNeTFNXCrVHysAa3eFbuzD8_bLSsgTKC8SzHxRVSj5eN86vBPo_1fNfE7SHTYhWowjY4E_wuiC13yoj";
        var publicKey = (
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+" +
                "Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii" +
                "1D3jaW6pmGVJFhodzC31cy5sfOYotrzF"
        );
        var privateKey = (
                "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p" +
                "E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz" +
                "MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw" +
                "8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU="
        );
        var alg = new JwtEs384();
        var key = alg.parseJwtKey(publicKey + " " + privateKey);

        var newJwtSign = alg.signature(exJwtBody, key);

        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign, key)));
        System.out.println(Assertions.assertDoesNotThrow(() -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign, key)));

        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + exJwtSign+"1", key));
        Assertions.assertThrows(Exception.class, () -> alg.toJwtObjectWithVerify(exJwtBody + "." + newJwtSign+"1", key));
    }
}
