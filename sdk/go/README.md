# KeyPilot Go SDK / Go SDK说明

## English

The Go SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally.

### Installation

After the `sdk/go/v0.1.0` tag is published:

```bash
go get github.com/agivector/keypilot/sdk/go@v0.1.0
```

Before that tag exists, use a local `replace` directive:

```go
require github.com/agivector/keypilot/sdk/go v0.0.0

replace github.com/agivector/keypilot/sdk/go => ../keypilot/sdk/go
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

The default `1=STRICT` mode refreshes every 60 seconds. With a reachable JWKS endpoint, a cached key removed from JWKS is rejected at the next refresh boundary. `2=AVAILABLE` uses `max_stale` instead and does not provide the 60-second revocation SLA.

### Test

```bash
go test -race ./...
```

## 简体中文

Go SDK绑定一个可信 `issuer` 和固定 JWKS地址，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签。

`sdk/go/v0.1.0` Tag发布后可执行 `go get github.com/agivector/keypilot/sdk/go@v0.1.0`；Tag存在前，本地开发请使用 `replace` 指向本仓库的 `sdk/go`。原始签名字节使用 `Verify`，无填充 Base64URL签名使用 `VerifyBase64URL`。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。默认 STRICT每 60秒刷新，网络正常时已移除密钥在下一刷新边界拒绝；AVAILABLE不承诺该 SLA。生产 JWKS地址必须使用 HTTPS。
