# KeyPilot Java SDK

- 作者：vectorshi
- 创建时间：2026-11-25
- 状态：开发中

Maven 坐标：

```xml
<dependency>
    <groupId>io.github.codepunk-gm</groupId>
    <artifactId>keypilot-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

Java 包名：

```java
import io.github.codepunkgm.keypilot.Verifier;
```

SDK 绑定一个可信 `issuer` 和固定 `jwksUrl`，在本地缓存 RSA 公钥并支持 RS256、PS256 验签。
