# KeyPilot Examples / 示例说明

## English

The repository contains minimal runnable examples for Go, Python, and Java. Each example reads the JWKS URL and optional verification input from environment variables.

The recommended way to run every example against a real KeyPilot Docker container is:

```bash
make e2e
```

The script builds the server, creates a test issuer, imports and activates the shared public test keys, and runs all three examples.

Important environment variables:

| Variable | Description |
| --- | --- |
| `KEYPILOT_EXAMPLE_ISSUER` | Trusted issuer identifier |
| `KEYPILOT_EXAMPLE_JWKS_URL` | Fixed trusted JWKS URL |
| `KEYPILOT_EXAMPLE_KID` | Key identifier |
| `KEYPILOT_EXAMPLE_ALGORITHM` | Numeric algorithm code |
| `KEYPILOT_EXAMPLE_PAYLOAD` | Unpadded Base64URL payload |
| `KEYPILOT_EXAMPLE_SIGNATURE` | Unpadded Base64URL signature |

The built-in values are test vectors only and must not be used in production.

## 简体中文

仓库提供 Go、Python、Java 三种最小可运行示例。每个示例都通过环境变量读取 JWKS地址和可选验签输入。

推荐执行 `make e2e`：脚本会构建真实 KeyPilot Docker容器、创建测试签发方、导入并激活共享测试公钥，然后运行三种语言示例。

示例内置数据只用于测试，禁止用于生产环境。
