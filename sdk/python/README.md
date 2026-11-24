# KeyPilot Python SDK / Python SDK说明

## English

The Python SDK binds one trusted issuer to one fixed JWKS URL, caches the complete valid RSA key set, and verifies RS256 or PS256 signatures locally.

### Current installation

The package is not yet published to PyPI. Install it from the repository:

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

### Test

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 简体中文

Python SDK绑定一个可信 `issuer` 和固定 `jwks_url`，完整缓存有效 RSA公钥集合，并在本地完成 RS256或 PS256验签。

当前包尚未发布到 PyPI，请从仓库执行 `pip install -e ./sdk/python` 安装。`signature` 支持原始字节或无填充 Base64URL字符串。

SDK支持 ETag、完整缓存替换、未知 `kid` 刷新冷却，以及 `STRICT=1`、`AVAILABLE=2` 失败策略。生产 JWKS地址必须使用 HTTPS。
