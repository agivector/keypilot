# KeyPilot

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/agivector/keypilot/actions/workflows/ci.yml/badge.svg)](https://github.com/agivector/keypilot/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](server/go.mod)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg)](sdk/python/pyproject.toml)
[![Java](https://img.shields.io/badge/Java-17+-ED8B00.svg)](sdk/java/pom.xml)

KeyPilot 是一个轻量、可自托管的公钥分发服务，并提供行为一致的 Go、Python、Java 本地验签 SDK。它帮助中小企业摆脱“每个项目手工复制 RSA 公钥”的维护方式，统一处理密钥轮换、退役、吊销和审计。

> **项目状态：** Alpha。服务端、事务型 SQLite存储、备份恢复工具、RS256/PS256 三语言 SDK、共享测试向量、Docker部署、端到端验证和发布流水线已经实现。正式生产接入仍需企业结合自身环境完成安全评审、TLS入口、密钥管理、监控和恢复演练。

## 为什么需要 KeyPilot？

很多团队在多个项目中使用签名验签，但公钥仍通过配置文件手工维护：

- 公钥散落在多个项目中，更新时容易遗漏。
- 密钥轮换需要协调多个服务同时发版。
- Java、Python、Go 的缓存、刷新和失败策略不一致。
- 退役或吊销密钥难以在所有项目中及时移除。
- 中小团队需要合规和审计能力，但不希望先建设大型安全平台。

KeyPilot 统一管理**验签公钥**，实际验签仍在业务应用内部本地完成，不让每次验签依赖中心服务。

## 工作方式

```text
                    管理 API
                       │
                       ▼
签名方/管理员 ───► KeyPilot 服务端 ───► SQLite存储
                       │
                       │ 标准 JWKS + ETag
                       ▼
              Go / Python / Java SDK
                       │
                       ▼
                    本地验签
```

1. 管理员将 RSA 公钥 JWK 导入 KeyPilot。
2. 密钥按照 `PRE_ACTIVE`、`ACTIVE`、`RETIRED` 等数值状态流转。
3. KeyPilot 通过标准 JWKS接口发布可信公钥。
4. SDK完整缓存 JWKS，并在本地完成验签，不会每次请求中心服务。
5. SDK支持 ETag刷新，并删除最新完整 JWKS中已经不存在的密钥。

## 已实现能力

### 服务端

- 使用 `issuer + kid` 建立可信密钥边界。
- 导入 RSA 公钥 JWK，并拒绝私钥字段。
- 数值型密钥生命周期和稳定数值错误码。
- 标准 JWKS发布，支持 `ETag` 和 `Cache-Control`。
- Bearer Token保护的管理 API。
- SQLite事务持久化，业务记录与审计记录原子提交。
- 支持在线一致性备份，以及停机完整性校验和原子恢复。
- 具名管理员身份、被拒绝操作审计和密钥状态变更前后记录。
- 非 root Docker镜像、健康检查和优雅停机。

### SDK

- Go、Python、Java 三种实现保持相同语义。
- 支持 RS256、PS256 本地验签。
- 固定可信 JWKS地址，不信任业务请求临时传入的 URL。
- 使用完整集合替换缓存，不永久合并旧密钥。
- 未知 `kid` 刷新冷却，避免随机请求放大网络访问。
- 支持 `STRICT=1`、`AVAILABLE=2` 两种失败策略。
- 暴露稳定的 `6000-6999` SDK错误码。
- 三种语言共同执行同一套测试向量。

### 后续密码能力

- SM2 将通过现有验签边界扩展。
- SM4 是对称加密算法，将使用独立 `Cipher` 接口，不会混入验签方法。

## 当前不包含

- 私钥托管或私钥导出。
- 中心化远程验签服务。
- KMS、HSM、审批工作流或 Web管理后台。
- 多实例主动-主动并发写同一个 SQLite数据库文件。
- Redis、消息队列或微服务部署要求。

## 快速开始

### 1. 构建镜像

```bash
git clone https://github.com/agivector/keypilot.git
cd keypilot
docker build -t keypilot:dev .
```

### 2. 启动 KeyPilot

管理 Token长度必须不少于16个字符：

```bash
docker run --rm \
  --name keypilot \
  -p 8080:8080 \
  -e KEYPILOT_ADMIN_ID='security-operator' \
  -e KEYPILOT_ADMIN_TOKEN='replace-with-a-strong-token' \
  -v keypilot-data:/data \
  keypilot:dev
```

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

预期响应：

```json
{"status":"ok"}
```

包含存储访问检查的就绪探针：

```bash
curl http://127.0.0.1:8080/readyz
```

预期响应：

```json
{"status":"ready"}
```

### 3. 创建签发方

```bash
curl -X POST http://127.0.0.1:8080/admin/v1/issuers \
  -H 'Authorization: Bearer replace-with-a-strong-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "issuer": "payment-service",
    "displayName": "Payment Service"
  }'
```

### 4. 导入并激活 RSA 公钥

```bash
curl -X POST http://127.0.0.1:8080/admin/v1/issuers/payment-service/keys \
  -H 'Authorization: Bearer replace-with-a-strong-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "description": "2026 rotation key",
    "jwk": {
      "kty": "RSA",
      "kid": "payment-2026-01",
      "use": "sig",
      "alg": "PS256",
      "n": "replace-with-base64url-modulus",
      "e": "AQAB"
    }
  }'

curl -X PATCH http://127.0.0.1:8080/admin/v1/issuers/payment-service/keys/payment-2026-01/status \
  -H 'Authorization: Bearer replace-with-a-strong-token' \
  -H 'Content-Type: application/json' \
  -d '{"status":2}'
```

### 5. 获取 JWKS

```bash
curl -i http://127.0.0.1:8080/v1/issuers/payment-service/.well-known/jwks.json
```

完整 API契约位于 [`api/openapi.yaml`](api/openapi.yaml)。

## SDK 发布状态

三种 SDK已具备 Tag驱动的正式发布流水线，但在对应公共仓库页面真实存在前，**不能视为已经发布**。首个发布成功前，请直接从本仓库使用。

| 语言 | 源码 | 本地安装方式 |
| --- | --- | --- |
| Go | [`sdk/go`](sdk/go) | `sdk/go/v0.1.0` Tag存在后执行 `go get github.com/agivector/keypilot/sdk/go@v0.1.0` |
| Python | [`sdk/python`](sdk/python) | `pip install -e ./sdk/python` |
| Java | [`sdk/java`](sdk/java) | `mvn -f sdk/java/pom.xml install` |

## SDK 使用示例

SDK初始化时绑定可信 `issuer` 和固定 JWKS地址。业务方必须传入签名方实际使用的原始载荷字节，KeyPilot不会自动排序或序列化业务数据。

### Go

```go
import (
    "context"

    keypilot "github.com/agivector/keypilot/sdk/go"
)

verifier, err := keypilot.NewVerifier(keypilot.Config{
    Issuer:  "payment-service",
    JWKSURL: "https://keys.example.com/v1/issuers/payment-service/.well-known/jwks.json",
    AllowedAlgorithms: []keypilot.CryptoAlgorithm{
        keypilot.CryptoAlgorithmPS256,
    },
})
if err != nil {
    panic(err)
}

result, err := verifier.Verify(
    context.Background(),
    payloadBytes,
    signatureBytes,
    "payment-2026-01",
    keypilot.CryptoAlgorithmPS256,
)
```

### Python

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

### Java

```java
import io.github.agivector.keypilot.Config;
import io.github.agivector.keypilot.CryptoAlgorithm;
import io.github.agivector.keypilot.VerificationResult;
import io.github.agivector.keypilot.Verifier;
import java.util.Set;

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

## 缓存失败策略

| 编码 | 模式 | 行为 |
| --- | --- | --- |
| `1` | `STRICT` | 达到 `refresh_interval` 后同步刷新；刷新失败返回 `CACHE_EXPIRED` 并拒绝验签。 |
| `2` | `AVAILABLE` | 达到刷新周期后异步刷新，并在 `max_stale` 范围内继续使用最后一次完整有效缓存。 |

超过 `max_stale` 后，两种模式都必须刷新成功，否则拒绝继续使用旧缓存。

### 吊销生效 SLA

使用默认 `1=STRICT` 策略且 KeyPilot网络可达时，已缓存密钥从 JWKS移除后，最迟在下一个 60秒刷新边界被拒绝。服务端默认发布 `Cache-Control: max-age=30`，避免合规缓存中间层延长该窗口。`2=AVAILABLE` 明确优先可用性，不承诺 60秒吊销 SLA；刷新持续失败时，其旧密钥窗口上限由 `max_stale` 决定。

## 密钥轮换流程

1. 将下一把公钥导入为 `1=PRE_ACTIVE`。
2. 预留时间让 SDK缓存获取新密钥。
3. 将新密钥调整为 `2=ACTIVE`，签名方开始使用新 `kid`。
4. 将旧密钥调整为 `3=RETIRED`，保留历史签名验证窗口。
5. 验证窗口结束后调整为 `4=ARCHIVED`；安全事件发生时立即调整为 `5=REVOKED`。

平滑轮换期间，KeyPilot允许同时发布多把 ACTIVE或 RETIRED密钥。

## 审计查询

管理变更和认证失败会持久化为审计记录。使用管理 Token查询最新记录：

```bash
curl 'http://127.0.0.1:8080/admin/v1/audits?issuer=payment-service&limit=100' \
  -H 'Authorization: Bearer replace-with-a-strong-token'
```

每条记录包含请求 ID、配置的管理员身份、客户端 IP、操作和结果枚举、关联的 `issuer` 和 `kid`、状态变更、错误码、原因以及 `create_time`。

## 配置说明

### 服务端环境变量

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `KEYPILOT_ADMIN_TOKEN` | 是 | 无 | 管理 API Bearer Token，至少16个字符 |
| `KEYPILOT_ADMIN_ID` | 否 | `default-admin` | 写入审计记录的稳定管理员身份 |
| `KEYPILOT_ADDR` | 否 | `:8080` | HTTP监听地址 |
| `KEYPILOT_STORAGE_TYPE` | 否 | `2` | 数值存储枚举：`1=JSON_FILE`、`2=SQLITE` |
| `KEYPILOT_DATA_FILE` | 否 | `data/keypilot.db` | 存储文件；JSON默认 `data/keypilot.json`，Docker使用 `/data/keypilot.db` |
| `KEYPILOT_JWKS_MAX_AGE` | 否 | `30` | JWKS公共缓存秒数，不应高于要求的吊销窗口 |
| `KEYPILOT_SHUTDOWN_TIMEOUT` | 否 | `10s` | 优雅停机超时 |

### SDK默认值

| 配置 | 默认值 |
| --- | --- |
| `refresh_interval` | 1分钟 |
| `request_timeout` | 3秒 |
| `unknown_kid_cooldown` | 30秒 |
| `max_stale` | 15分钟 |
| `failure_mode` | `1=STRICT` |

生产环境 JWKS地址必须使用 HTTPS。只有 localhost和回环地址测试允许使用 HTTP。

## 备份与恢复

KeyPilot运行期间创建一致性备份：

```bash
docker run --rm --volumes-from keypilot \
  --entrypoint keypilotctl keypilot:dev \
  backup --data-file /data/keypilot.db --output /data/backups/keypilot.db
```

恢复时必须先停止 KeyPilot，确保没有进程持有目标数据库：

```bash
docker stop keypilot
docker run --rm -v keypilot-data:/data \
  --entrypoint keypilotctl keypilot:dev \
  restore --input /data/backups/keypilot.db --data-file /data/keypilot.db
```

备份命令使用 SQLite一致性快照机制。恢复会执行 `PRAGMA integrity_check`，复制到临时文件并 `fsync`，清理旧 WAL旁路文件后原子替换目标数据库。生产环境应保留加密的异地备份并定期恢复演练；从未实际恢复过的备份不能视为有效灾备。

## 生产检查清单

- 使用持续维护的反向代理或负载均衡终止 TLS，并通过网络策略限制管理 API。
- 从密钥管理系统注入 `KEYPILOT_ADMIN_TOKEN`，定期轮换，并配置具名 `KEYPILOT_ADMIN_ID`。
- 将 `/data` 放在持久化存储上，定时异地备份并执行恢复演练。
- 监控 `/readyz`、HTTP错误率、磁盘容量、SDK刷新失败和审计事件。
- 需要 60秒吊销 SLA时使用 `1=STRICT`；只有接受旧密钥窗口后才选择 `2=AVAILABLE`。
- 每个 SQLite数据库文件只运行一个写实例，重启和故障转移由外部编排完成，不使用共享文件并发写。

## 安全边界

- KeyPilot只保存和发布公钥。
- RSA私钥 JWK字段会被拒绝。
- SDK不会从不可信业务请求提供的 URL下载公钥。
- 每个 Verifier必须显式配置算法白名单。
- 时间戳、Nonce、Audience、防重放和业务权限仍由接入方负责。
- 测试向量和示例密钥不得用于生产环境。

安全问题报告方式请阅读 [`SECURITY.zh-CN.md`](SECURITY.zh-CN.md)。

## 开发与验证

完整验证流程只要求本地安装 Docker：

```bash
make docker-verify
```

该命令运行服务端检查、Go SDK竞态检测、Python 3.12测试和 Java 17目标字节码测试。

验证可正式发布的 Python和 Java制品：

```bash
make release-package-check
```

执行真实端到端验证：

```bash
make e2e
```

端到端脚本会构建服务端镜像、创建签发方、导入并激活共享测试公钥，然后让三种 SDK连接真实 JWKS接口完成验签。

## 项目结构

```text
keypilot/
├── api/             # OpenAPI契约
├── server/          # Go服务端
├── sdk/             # Go、Python、Java SDK
├── examples/        # 三语言可运行示例
├── test-vectors/    # 跨语言密码测试向量
├── scripts/         # 端到端验证脚本
├── Dockerfile
└── Makefile
```

## 发布流水线

推送根 Tag（例如 `v0.1.0`）后，流水线会执行完整验证，通过 PyPI Trusted Publishing发布 `keypilot-sdk==0.1.0`，发布 `io.github.agivector:keypilot-sdk:0.1.0` 到 Maven Central，发布多架构镜像 `ghcr.io/agivector/keypilot:0.1.0`，创建 `sdk/go/v0.1.0` 和 GitHub Release。仓库所有者需要先配置 `pypi`、`maven-central` environments、PyPI Trusted Publisher、Maven Central命名空间和 Token，以及 GPG密钥 Secrets。

## 路线图

- 完成首次公共仓库真实发布和兼容性矩阵验证。
- 只有在明确需要主动-主动多实例时，再增加独立外部数据库实现。
- 增加 SM2验签和跨语言共享测试向量。
- 增加独立 SM4加解密接口，不将加密能力混入验签。
- 完善发布自动化和兼容性测试。

## 参与贡献

欢迎提交贡献。开始前请阅读 [`CONTRIBUTING.zh-CN.md`](CONTRIBUTING.zh-CN.md)，并遵守 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

## 许可证

KeyPilot 使用 [MIT License](LICENSE)。
