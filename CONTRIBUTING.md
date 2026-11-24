# Contributing to KeyPilot

[English](CONTRIBUTING.md) | [简体中文](CONTRIBUTING.zh-CN.md)

Thank you for helping improve KeyPilot. The project favors small, reviewable changes, stable public contracts, and evidence-backed verification.

## Before You Start

- Search existing issues before opening a new one.
- Discuss large API, storage, cryptography, or compatibility changes in an issue first.
- Never include production private keys, tokens, customer data, or vulnerability details in a public issue.

## Development Setup

Docker is the recommended development dependency because it provides the required Go, Python, and Java runtimes.

```bash
git clone https://github.com/codepunk-gm/keypilot.git
cd keypilot
make docker-verify
```

Run the live server and all SDK examples:

```bash
make e2e
```

## Coding Requirements

- Keep the architecture simple and avoid unrelated refactoring.
- Preserve numeric enum values and stable error codes.
- Use `create_time`, `update_time`, and other `*_time` fields; do not introduce `*_at` fields.
- Every source file, type, and method must include author, creation date, description, parameter, and return documentation according to `AGENTS.md`.
- The author used in project source comments is `vectorshi`.
- Add or update unit tests for every behavior change.
- Do not mix SM4 encryption into signature verification APIs.
- Never add private-key publication or export behavior.

## Pull Request Checklist

- [ ] The change has a clear, limited purpose.
- [ ] Relevant unit tests were added or updated.
- [ ] `make docker-verify` passes.
- [ ] `make e2e` passes when the change affects server/SDK integration.
- [ ] Public API, configuration, error-code, or behavior changes are documented.
- [ ] No secrets, private keys, generated build output, or unrelated files are included.
- [ ] Backward compatibility impact is explained.

## Commit Messages

Use concise imperative messages. Conventional Commit prefixes are recommended:

```text
feat: add database storage interface
fix: preserve valid cache after invalid JWKS refresh
docs: clarify Java SDK installation
test: add SM2 cross-language vectors
```

## Reporting Security Issues

Do not report vulnerabilities in public issues. Follow [`SECURITY.md`](SECURITY.md).
