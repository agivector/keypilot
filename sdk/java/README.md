# KeyPilot Java SDK / Java SDK说明

## English

The Java SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally. It targets Java 17 or later.

### Installation

After version `0.1.0` is visible on Maven Central, use:

```xml
<dependency>
    <groupId>io.github.agivector</groupId>
    <artifactId>keypilot-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

Before the first successful registry release, install it into the local Maven repository:

```bash
mvn -f sdk/java/pom.xml install
```

Then use the local artifact:

```xml
<dependency>
    <groupId>io.github.agivector</groupId>
    <artifactId>keypilot-sdk</artifactId>
    <version>0.1.0</version>
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

The Java package is `io.github.agivector.keypilot`.

The default `1=STRICT` mode refreshes every 60 seconds. With a reachable JWKS endpoint, a cached key removed from JWKS is rejected at the next refresh boundary. `2=AVAILABLE` uses `max_stale` instead and does not provide the 60-second revocation SLA.

### Test

```bash
mvn -f sdk/java/pom.xml test
```

## 简体中文

Java SDK绑定一个可信 `issuer` 和固定 `jwksUrl`，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签，最低支持 Java 17。

`0.1.0` 在 Maven Central真实可见后引用 `io.github.agivector:keypilot-sdk:0.1.0`；首次发布成功前，请先执行 `mvn -f sdk/java/pom.xml install` 安装到本地 Maven仓库。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。默认 STRICT每 60秒刷新，网络正常时已移除密钥在下一刷新边界拒绝；AVAILABLE不承诺该 SLA。生产 JWKS地址必须使用 HTTPS。
