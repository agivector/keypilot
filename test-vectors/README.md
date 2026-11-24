# KeyPilot Cross-Language Test Vectors / 跨语言测试向量

## English

This directory is the shared verification baseline for the Go, Python, and Java SDKs.

### Files

- `keys/rsa-public-jwks.json`: RSA public keys only; no private key material is stored.
- `cases/signatures.json`: fixed payloads, signatures, numeric algorithms, and expected results.

### Encoding

- `payload_base64` uses unpadded Base64URL.
- `signature_base64url` uses unpadded Base64URL.
- `algorithm` uses the numeric `CryptoAlgorithm` enum.
- `expected_error_code` uses the numeric `SdkErrorCode` enum and is `null` for success.

Every SDK change affecting cryptography or error semantics must run all vectors. These keys and signatures are test data and must never be used in production.

## 简体中文

本目录是 Go、Python、Java SDK验签行为的共同测试基线。

- `keys/rsa-public-jwks.json` 只包含 RSA公钥，不保存任何私钥材料。
- `cases/signatures.json` 保存固定载荷、签名、数值算法和预期结果。
- `payload_base64`、`signature_base64url` 使用无填充 Base64URL。
- `algorithm` 使用 `CryptoAlgorithm` 数值枚举。
- `expected_error_code` 使用 `SdkErrorCode` 数值枚举，成功时为 `null`。

任何影响密码实现或错误语义的 SDK修改都必须运行全部向量。测试密钥和签名禁止用于生产环境。
