# KeyPilot Go SDK / Go SDK说明

## English

The Go SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally.

### Current installation

The module is not yet published as a tagged release. During local development, use a `replace` directive:

```go
require github.com/codepunk-gm/keypilot/sdk/go v0.0.0

replace github.com/codepunk-gm/keypilot/sdk/go => ../keypilot/sdk/go
```

### Usage

```go
verifier, err := keypilot.NewVerifier(keypilot.Config{
    Issuer:  "payment-service",
    JWKSURL: "https://keys.example.com/v1/issuers/payment-service/.well-known/jwks.json",
    AllowedAlgorithms: []keypilot.CryptoAlgorithm{
        keypilot.CryptoAlgorithmPS256,
    },
})

result, err := verifier.Verify(
    context.Background(),
    payloadBytes,
    signatureBytes,
    "payment-2026-01",
    keypilot.CryptoAlgorithmPS256,
)
```

The signature may also be provided as unpadded Base64URL through `VerifyBase64URL`.

### Test

```bash
go test -race ./...
```

## 简体中文

Go SDK绑定一个可信 `issuer` 和固定 JWKS地址，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签。

当前模块尚未发布正式 Tag，本地开发请使用 `replace` 指向本仓库的 `sdk/go`。原始签名字节使用 `Verify`，无填充 Base64URL签名使用 `VerifyBase64URL`。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。生产 JWKS地址必须使用 HTTPS。
