# KeyPilot

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/agivector/keypilot/actions/workflows/ci.yml/badge.svg)](https://github.com/agivector/keypilot/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8.svg)](server/go.mod)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB.svg)](sdk/python/pyproject.toml)
[![Java](https://img.shields.io/badge/Java-17+-ED8B00.svg)](sdk/java/pom.xml)

KeyPilot is a lightweight, self-hosted public-key distribution service with consistent verification SDKs for Go, Python, and Java. It helps small and medium-sized teams stop copying RSA public keys into every application and provides a controlled path for key rotation, retirement, revocation, and audit.

> **Project status:** Alpha. The core server, transactional SQLite storage, backup/restore tooling, RS256/PS256 SDKs, shared test vectors, Docker deployment, end-to-end verification, and release workflows are implemented. Production adoption still requires organization-specific security review, TLS ingress, secret management, monitoring, and recovery drills.

## Why KeyPilot?

Many teams verify signatures in several applications but still manage public keys manually:

- Public keys are copied into configuration files and become difficult to update.
- Key rotation requires coordinated releases across many services.
- Different languages implement refresh, caching, and failure handling differently.
- Revoked or retired keys are difficult to remove consistently.
- Teams need an auditable solution without adopting a large security platform.

KeyPilot centralizes **public verification key management** while keeping signature verification local inside each application.

## How It Works

```text
                    management API
                         │
                         ▼
Signer/Admin ─────► KeyPilot Server ─────► SQLite storage
                         │
                         │ standard JWKS + ETag
                         ▼
                Go / Python / Java SDK
                         │
                         ▼
                  local verification
```

1. An administrator imports an RSA public JWK into KeyPilot.
2. The key moves through a numeric lifecycle such as `PRE_ACTIVE`, `ACTIVE`, and `RETIRED`.
3. KeyPilot publishes trusted keys through a standard JWKS endpoint.
4. Each SDK caches the complete JWKS locally and verifies signatures without a network request per operation.
5. SDKs refresh with ETag support and remove keys that disappear from the latest valid JWKS response.

## Features

### Server

- Issuer management using `issuer + kid` as the trust boundary.
- RSA public JWK import with private-key field rejection.
- Numeric key lifecycle and stable numeric error codes.
- Standard JWKS publication with `ETag` and `Cache-Control`.
- Bearer-token protected administration API.
- Transactional SQLite persistence with atomic business and audit writes.
- Online consistent backup and stopped-service integrity-checked atomic restore.
- Named administrator identity, rejected-operation audits, and before/after key status history.
- Non-root Docker image, health check, and graceful shutdown.

### SDKs

- Go, Python, and Java implementations with matching behavior.
- RS256 and PS256 local verification.
- Fixed trusted JWKS URL; request-provided URLs are never trusted.
- Complete cache replacement instead of permanent key merging.
- Unknown-`kid` refresh cooldown to limit request amplification.
- `STRICT=1` and `AVAILABLE=2` stale-cache policies.
- Stable `6000-6999` SDK error codes.
- Shared cross-language test vectors.

### Planned Cryptography

- SM2 verification will be added through the existing verifier boundary.
- SM4 is symmetric encryption and will use a separate cipher API instead of being added to signature verification.

## Non-Goals

The current release does **not** provide:

- Private-key storage or private-key export.
- Centralized remote signature verification.
- KMS, HSM, approval workflow, or Web administration UI.
- Active-active multi-instance writes to one SQLite database file.
- Redis, message queues, or microservice deployment requirements.

## Quick Start

### 1. Build the server image

```bash
git clone https://github.com/agivector/keypilot.git
cd keypilot
docker build -t keypilot:dev .
```

### 2. Start KeyPilot

Use an administration token with at least 16 characters:

```bash
docker run --rm \
  --name keypilot \
  -p 8080:8080 \
  -e KEYPILOT_ADMIN_ID='security-operator' \
  -e KEYPILOT_ADMIN_TOKEN='replace-with-a-strong-token' \
  -v keypilot-data:/data \
  keypilot:dev
```

Check health:

```bash
curl http://127.0.0.1:8080/healthz
```

Expected response:

```json
{"status":"ok"}
```

Check readiness, including persistence access:

```bash
curl http://127.0.0.1:8080/readyz
```

Expected response:

```json
{"status":"ready"}
```

### 3. Create an issuer

```bash
curl -X POST http://127.0.0.1:8080/admin/v1/issuers \
  -H 'Authorization: Bearer replace-with-a-strong-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "issuer": "payment-service",
    "displayName": "Payment Service"
  }'
```

### 4. Import and activate an RSA public key

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

### 5. Read the JWKS

```bash
curl -i http://127.0.0.1:8080/v1/issuers/payment-service/.well-known/jwks.json
```

The full API contract is available in [`api/openapi.yaml`](api/openapi.yaml).

## SDK Installation Status

The SDKs are publishable through the Tag-driven release workflow but are **not considered publicly available until the corresponding registry pages exist**. Before the first successful release, use them directly from this repository.

| Language | Source | Local installation |
| --- | --- | --- |
| Go | [`sdk/go`](sdk/go) | `go get github.com/agivector/keypilot/sdk/go@v0.1.0` after the `sdk/go/v0.1.0` tag exists |
| Python | [`sdk/python`](sdk/python) | `pip install -e ./sdk/python` |
| Java | [`sdk/java`](sdk/java) | `mvn -f sdk/java/pom.xml install` |

## SDK Usage

All SDKs bind a verifier to one trusted issuer and one fixed JWKS URL. Pass the exact payload bytes used by the signer; KeyPilot does not reorder or serialize business data.

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

## Cache Failure Policies

| Code | Mode | Behavior |
| --- | --- | --- |
| `1` | `STRICT` | Once `refresh_interval` is reached, refresh synchronously. Reject verification with `CACHE_EXPIRED` if refresh fails. |
| `2` | `AVAILABLE` | Refresh asynchronously after `refresh_interval` and continue using the last complete valid cache until `max_stale`. |

Both modes reject stale data after `max_stale` unless a refresh succeeds.

### Revocation Effective SLA

With the default `1=STRICT` policy and a reachable KeyPilot endpoint, an already cached key removed from JWKS is rejected no later than the next 60-second refresh boundary. The server publishes `Cache-Control: max-age=30` by default so compliant intermediaries do not extend that window. `2=AVAILABLE` intentionally prioritizes availability and does not provide the 60-second revocation SLA; its upper bound is `max_stale` when refreshes fail.

## Key Rotation Workflow

1. Import the next public key as `1=PRE_ACTIVE`.
2. Allow SDK caches to receive the new key.
3. Change the key to `2=ACTIVE` and start signing with its `kid`.
4. Change the previous key to `3=RETIRED` while historical signatures still need verification.
5. Change it to `4=ARCHIVED` after the verification window ends, or `5=REVOKED` immediately for a security incident.

KeyPilot can publish multiple active or retired keys during a safe rotation window.

## Audit Query

Administration mutations and authentication failures are persisted as audit records. Query the newest records with the administration token:

```bash
curl 'http://127.0.0.1:8080/admin/v1/audits?issuer=payment-service&limit=100' \
  -H 'Authorization: Bearer replace-with-a-strong-token'
```

Each record includes the request ID, configured administrator identity, client IP, action and result enums, affected `issuer` and `kid`, status changes, error code, reason, and `create_time`.

## Configuration

### Server Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `KEYPILOT_ADMIN_TOKEN` | Yes | None | Administration Bearer token; minimum 16 characters |
| `KEYPILOT_ADMIN_ID` | No | `default-admin` | Stable administrator identity written to audit records |
| `KEYPILOT_ADDR` | No | `:8080` | HTTP listen address |
| `KEYPILOT_STORAGE_TYPE` | No | `2` | Numeric storage enum: `1=JSON_FILE`, `2=SQLITE` |
| `KEYPILOT_DATA_FILE` | No | `data/keypilot.db` | Storage path; JSON defaults to `data/keypilot.json`, Docker uses `/data/keypilot.db` |
| `KEYPILOT_JWKS_MAX_AGE` | No | `30` | Public JWKS cache duration in seconds; keep at or below the required revocation window |
| `KEYPILOT_SHUTDOWN_TIMEOUT` | No | `10s` | Graceful shutdown timeout |

### SDK Defaults

| Setting | Default |
| --- | --- |
| `refresh_interval` | 1 minute |
| `request_timeout` | 3 seconds |
| `unknown_kid_cooldown` | 30 seconds |
| `max_stale` | 15 minutes |
| `failure_mode` | `1=STRICT` |

Production JWKS URLs must use HTTPS. Plain HTTP is accepted only for localhost and loopback testing.

## Backup and Restore

Create a consistent backup while KeyPilot is running:

```bash
docker run --rm --volumes-from keypilot \
  --entrypoint keypilotctl keypilot:dev \
  backup --data-file /data/keypilot.db --output /data/backups/keypilot.db
```

Restore requires KeyPilot to be stopped so no process holds the target database:

```bash
docker stop keypilot
docker run --rm -v keypilot-data:/data \
  --entrypoint keypilotctl keypilot:dev \
  restore --input /data/backups/keypilot.db --data-file /data/keypilot.db
```

The backup command uses SQLite's consistent snapshot mechanism. Restore runs `PRAGMA integrity_check`, copies to a temporary file, synchronizes it, removes stale WAL sidecars, and atomically replaces the target. Keep encrypted off-host backups and test recovery regularly; a backup that has never been restored is not a verified recovery plan.

## Production Checklist

- Terminate TLS in a maintained reverse proxy or load balancer and restrict the administration API by network policy.
- Inject `KEYPILOT_ADMIN_TOKEN` from a secret manager; rotate it and use a named `KEYPILOT_ADMIN_ID`.
- Persist `/data` on durable storage, schedule off-host backups, and run restore drills.
- Monitor `/readyz`, HTTP error rates, storage capacity, SDK refresh failures, and audit events.
- Use `1=STRICT` for the documented 60-second revocation SLA; choose `2=AVAILABLE` only after accepting its stale-key window.
- Run one writer instance per SQLite database file. Use external orchestration for restart and failover, not concurrent shared-file writers.

## Security Model

- KeyPilot stores and publishes public keys only.
- RSA private JWK parameters are rejected.
- SDKs never download keys from a URL supplied by an untrusted request.
- Algorithms must be explicitly allowed by each verifier.
- Business timestamp, nonce, audience, replay protection, and authorization checks remain the responsibility of the integrating application.
- Test vectors and example keys must never be used in production.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting.

## Development and Verification

Docker is the only required local dependency for the complete verification flow.

```bash
make docker-verify
```

This runs server tests, Go SDK race detection, Python 3.12 tests, and Java tests targeting Java 17.

Validate publishable Python and Java packages:

```bash
make release-package-check
```

Run the real end-to-end flow:

```bash
make e2e
```

The end-to-end script builds the server image, creates an issuer, imports and activates the shared test keys, and runs all three SDK examples against the live JWKS endpoint.

## Project Layout

```text
keypilot/
├── api/             # OpenAPI contract
├── server/          # Go server
├── sdk/             # Go, Python, and Java SDKs
├── examples/        # Runnable language examples
├── test-vectors/    # Shared cryptographic test cases
├── scripts/         # End-to-end verification
├── Dockerfile
└── Makefile
```

## Release Pipeline

Pushing a root tag such as `v0.1.0` runs full verification, publishes `keypilot-sdk==0.1.0` to PyPI through Trusted Publishing, publishes `io.github.agivector:keypilot-sdk:0.1.0` to Maven Central, publishes multi-architecture `ghcr.io/agivector/keypilot:0.1.0`, creates `sdk/go/v0.1.0`, and creates the GitHub Release. Repository owners must first configure the `pypi` and `maven-central` environments, PyPI Trusted Publisher, Maven Central namespace/token, and GPG secrets documented in the workflow.

## Roadmap

- Complete the first externally verified registry release and compatibility matrix.
- Add a separate external database implementation only when active-active multi-instance operation is required.
- Add SM2 signature verification with shared cross-language vectors.
- Add an independent SM4 cipher API without mixing encryption into verification.
- Improve release automation and compatibility testing.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting changes and follow the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

KeyPilot is licensed under the [MIT License](LICENSE).
