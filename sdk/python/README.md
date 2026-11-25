# KeyPilot Python SDK / Python SDK说明

## English

The Python SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally.

### Installation

After version `0.1.0` is visible on PyPI:

```bash
pip install keypilot-sdk==0.1.0
```

Before the first successful registry release, install it from the repository:

```bash
pip install -e ./sdk/python
```

### Usage

```python
from keypilot import Config, CryptoAlgorithm, Verifier

verifier = Verifier(Config(
    issuer="payment-service",
    jwks_url="https://keys.example.com/v1/issuers/payment-service/.well-known/jwks.json",
    allowed_algorithms=frozenset({CryptoAlgorithm.PS256}),
))

result = verifier.verify(
    payload=payload_bytes,
    signature=signature_bytes,
    kid="payment-2026-01",
    algorithm=CryptoAlgorithm.PS256,
)
```

`signature` accepts raw bytes or unpadded Base64URL text.

The default `1=STRICT` mode refreshes every 60 seconds. With a reachable JWKS endpoint, a cached key removed from JWKS is rejected at the next refresh boundary. `2=AVAILABLE` uses `max_stale` instead and does not provide the 60-second revocation SLA.

### Test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 简体中文

Python SDK绑定一个可信 `issuer` 和固定 `jwks_url`，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签。

`0.1.0` 在 PyPI真实可见后执行 `pip install keypilot-sdk==0.1.0`；首次发布成功前，请从仓库执行 `pip install -e ./sdk/python`。`signature` 支持原始字节或无填充 Base64URL字符串。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。默认 STRICT每 60秒刷新，网络正常时已移除密钥在下一刷新边界拒绝；AVAILABLE不承诺该 SLA。生产 JWKS地址必须使用 HTTPS。
