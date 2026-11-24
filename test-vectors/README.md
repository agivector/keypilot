# KeyPilot 跨语言测试向量

- 作者：vectorshi
- 创建时间：2026-11-25
- 状态：生效

本目录是 Python、Java、Go SDK 验签行为的共同测试基线。

## 文件说明

- `keys/rsa-public-jwks.json`：只包含 RSA 公钥，不保存私钥。
- `cases/signatures.json`：固定载荷、签名、算法和预期结果。

## 编码规则

- `payload_base64` 使用无填充 Base64URL。
- `signature_base64url` 使用无填充 Base64URL。
- `algorithm` 使用 `CryptoAlgorithm` 数值枚举。
- `expected_error_code` 使用 `SdkErrorCode` 数值枚举；成功时为 `null`。

任何 SDK 修改算法实现或错误语义时，都必须运行本目录中的全部用例。
