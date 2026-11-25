# 参与 KeyPilot 贡献

[English](CONTRIBUTING.md) | [简体中文](CONTRIBUTING.zh-CN.md)

感谢你帮助改进 KeyPilot。项目优先接受范围清晰、易于审查、保持公共契约稳定，并且具有验证证据的修改。

## 开始之前

- 创建 Issue前先搜索是否已有相同问题。
- API、存储、密码算法或兼容性等较大变更，应先通过 Issue讨论。
- 禁止在公开 Issue中提交生产私钥、Token、客户数据或漏洞细节。

## 开发环境

推荐只安装 Docker，由容器提供项目需要的 Go、Python、Java运行时。

```bash
git clone https://github.com/agivector/keypilot.git
cd keypilot
make docker-verify
```

运行真实服务端和三语言 SDK示例：

```bash
make e2e
```

## 编码要求

- 保持架构简单，不进行无关重构。
- 保持数值枚举和稳定错误码不变。
- 时间字段使用 `create_time`、`update_time` 和其他 `*_time`，禁止增加 `*_at` 字段。
- 所有源代码文件、类型和方法必须按照 `AGENTS.md` 包含作者、创建时间、描述、入参和返回值说明。
- 项目源代码注释中的作者统一为 `vectorshi`。
- 每项行为变更都必须新增或更新单元测试。
- 不得将 SM4加解密能力混入签名验签 API。
- 不得增加私钥发布或私钥导出能力。

## Pull Request检查清单

- [ ] 修改目标清晰，范围有限。
- [ ] 已增加或更新相关单元测试。
- [ ] `make docker-verify` 执行通过。
- [ ] 涉及服务端与 SDK联动时，`make e2e` 执行通过。
- [ ] 公共 API、配置、错误码或行为变化已更新说明。
- [ ] 不包含密钥、私钥、构建产物或无关文件。
- [ ] 已说明向后兼容影响。

## 提交信息

提交信息应简洁并说明动作，推荐使用 Conventional Commit前缀：

```text
feat: add database storage interface
fix: preserve valid cache after invalid JWKS refresh
docs: clarify Java SDK installation
test: add SM2 cross-language vectors
```

## 安全问题

请勿通过公开 Issue报告漏洞，具体方式见 [`SECURITY.zh-CN.md`](SECURITY.zh-CN.md)。
