# Security Policy

[English](SECURITY.md) | [简体中文](SECURITY.zh-CN.md)

## Supported Versions

KeyPilot is currently pre-1.0. Security fixes are applied to the latest `main` branch and the latest published release when releases become available.

## Reporting a Vulnerability

Please do not disclose security vulnerabilities in a public issue, discussion, or pull request.

Preferred reporting method:

1. Open the repository **Security** tab on GitHub.
2. Use **Report a vulnerability** to create a private security advisory.
3. Include affected versions, reproduction steps, impact, and any suggested mitigation.

If private vulnerability reporting is unavailable, open a public issue requesting a private contact channel **without including vulnerability details**.

## Sensitive Material

Never submit:

- Production private keys or complete private JWK values.
- Administration tokens or cloud credentials.
- Customer payloads or personally identifiable information.
- Public proof-of-concept exploits before a coordinated fix is available.

## Security Boundaries

- KeyPilot manages public verification keys; it is not a private-key vault.
- Integrators remain responsible for replay protection, timestamp checks, nonce handling, audience validation, and authorization.
- The JSON backend is single-instance storage and must not be shared by multiple writers.
- Production JWKS URLs must use HTTPS.

Reports will be acknowledged and evaluated on a best-effort basis. Resolution timing depends on severity, reproducibility, and maintainer availability.
