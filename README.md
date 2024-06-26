### SARO JWT
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt/badge.svg)](https://maven-badges.herokuapp.com/maven-central/me.saro/jwt)
[![GitHub license](https://img.shields.io/github/license/saro-lab/jwt.svg)](https://github.com/saro-lab/jwt/blob/master/LICENSE)

# QUICK START

## Gradle
```
implementation('me.saro:jwt:3.0.0')
```

## Maven
``` xml
<dependency>
  <groupId>me.saro</groupId>
  <artifactId>jwt</artifactId>
  <version>3.0.0</version>
</dependency>
```

## Kotlin Example / Test Code
- [Example](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/core/Example.kt)

| -  | 256                                                                                                  | 384                                                                                                  | 512                                                                                                  | Thread                                                                                                             |
|----|------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| ES | [ES256](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Es256.kt) | [ES384](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Es384.kt) | [ES512](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Es512.kt) | [ESThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/EsThreadTest.kt) |
| RS | [RS256](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Rs256.kt) | [RS384](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Rs384.kt) | [RS512](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Rs512.kt) | [RSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/RsThreadTest.kt) |
| PS | [PS256](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Ps256.kt) | [PS384](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Ps384.kt) | [PS512](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Ps512.kt) | [PSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/PsThreadTest.kt) |
| HS | [HS256](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Hs256.kt) | [HS384](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Hs384.kt) | [HS512](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/Hs512.kt) | [HSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/kotlin/me/saro/jwt/kotlin/alg/HsThreadTest.kt) |

## Java Example / Test Code
- [Example](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/core/Example.java)

| -  | 256                                                                                                | 384                                                                                                | 512                                                                                                | Thread                                                                                                           |
|----|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| ES | [ES256](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Es256.java) | [ES384](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Es384.java) | [ES512](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Es512.java) | [ESThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/EsThreadTest.java) |
| RS | [RS256](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Rs256.java) | [RS384](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Rs384.java) | [RS512](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Rs512.java) | [RSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/RsThreadTest.java) |
| PS | [PS256](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Ps256.java) | [PS384](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Ps384.java) | [PS512](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Ps512.java) | [PSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/PsThreadTest.java) |
| HS | [HS256](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Hs256.java) | [HS384](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Hs384.java) | [HS512](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/Hs512.java) | [HSThreadTest](https://github.com/saro-lab/jwt/blob/master/src/test/java/me/saro/jwt/java/alg/HsThreadTest.java) | 


## repository
- https://search.maven.org/artifact/me.saro/jwt
- https://mvnrepository.com/artifact/me.saro/jwt

## see
- [jwt.io](https://jwt.io)
- [가리사니의 조각들...](https://gs.saro.me)

