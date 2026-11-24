# KeyPilot Python SDK

- 作者：vectorshi
- 创建时间：2026-11-25
- 状态：开发中

Python SDK 绑定一个可信 `issuer` 和固定 `jwks_url`，在本地缓存 RSA 公钥并支持 RS256、PS256 验签。

```python
from keypilot import Config, CryptoAlgorithm, Verifier

verifier = Verifier(Config(
    issuer="payment-service",
    jwks_url="https://keys.example.com/v1/issuers/payment-service/.well-known/jwks.json",
    allowed_algorithms=frozenset({CryptoAlgorithm.PS256}),
))

result = verifier.verify(payload, signature, "payment-2026-01", CryptoAlgorithm.PS256)
```
