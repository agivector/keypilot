# KeyPilot Java SDK / Java SDK说明

## English

The Java SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally. It targets Java 17 or later.

### Current installation

The artifact is not yet published to Maven Central. Install it into the local Maven repository first:

```bash
mvn -f sdk/java/pom.xml install
```

Then use the local artifact:

```xml
<dependency>
    <groupId>io.github.codepunk-gm</groupId>
    <artifactId>keypilot-sdk</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

### Usage

```java
Verifier verifier = new Verifier(Config.builder()
    .issuer("payment-service")
    .jwksUrl("https://keys.example.com/v1/issuers/payment-service/.well-known/jwks.json")
    .allowedAlgorithms(Set.of(CryptoAlgorithm.PS256))
    .build());

VerificationResult result = verifier.verify(
    payloadBytes,
    signatureBytes,
    "payment-2026-01",
    CryptoAlgorithm.PS256
);
```

The Java package is `io.github.codepunkgm.keypilot`.

### Test

```bash
mvn -f sdk/java/pom.xml test
```

## 简体中文

Java SDK绑定一个可信 `issuer` 和固定 `jwksUrl`，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签，最低支持 Java 17。

当前构件尚未发布到 Maven Central，请先执行 `mvn -f sdk/java/pom.xml install` 安装到本地 Maven仓库，再引用 `io.github.codepunk-gm:keypilot-sdk:0.1.0-SNAPSHOT`。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。生产 JWKS地址必须使用 HTTPS。
