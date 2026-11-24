"""
Description: Demonstrates minimal Python SDK verification against a running KeyPilot JWKS endpoint.
Author: vectorshi
Created: 2026-11-25
"""

import base64
import os

from keypilot import Config, CryptoAlgorithm, Verifier

_DEFAULT_PAYLOAD = "b3JkZXJfaWQ9S1AtMjAyNi0wMDAxJmFtb3VudD0xOTk5JmN1cnJlbmN5PUNOWQ"
_DEFAULT_SIGNATURE = "o_ZG9_pHw8Mx-EKyO-dkph6KFX0Z8xmPo_LbWyk1hCPsiaRIboCnqjv7ZiMTrbAqHVPddJLd_ILND30viCKLm5ixFUwVUGRwV1nEyQ4DdycNZoq0zem_vDC1KIwGU_6phN4VDbZ2mu1q1a20BOx7piIu8XxLj3mwXpnga8O8eVKcwYhP5KNx7oINWBeNjg2wmOryxWl55lIRS8xs7XBPlSH-13yb4zWmjRfYMfn10iMY2bFqDGNM8Qc8y0W8xOyg5iodh3R6_5RhIWE-Bl-cw1LBUO2Y3twQl6UVWpmbMNDsVxq6ZnBzHOOU9Qoo8h4PhxwTcHL9oamnEPDbn12ezw"


def main() -> None:
    """
    Description: Loads example inputs from environment variables and verifies one signature.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns: None.
    """
    issuer = os.getenv("KEYPILOT_EXAMPLE_ISSUER", "vector-issuer")
    jwks_url = os.getenv(
        "KEYPILOT_EXAMPLE_JWKS_URL",
        "http://127.0.0.1:8080/v1/issuers/vector-issuer/.well-known/jwks.json",
    )
    kid = os.getenv("KEYPILOT_EXAMPLE_KID", "vector-rs256-2026-01")
    algorithm = CryptoAlgorithm(int(os.getenv("KEYPILOT_EXAMPLE_ALGORITHM", str(CryptoAlgorithm.RS256.value))))
    payload = _decode(os.getenv("KEYPILOT_EXAMPLE_PAYLOAD", _DEFAULT_PAYLOAD))
    signature = os.getenv("KEYPILOT_EXAMPLE_SIGNATURE", _DEFAULT_SIGNATURE)
    verifier = Verifier(Config(
        issuer=issuer,
        jwks_url=jwks_url,
        allowed_algorithms=frozenset({CryptoAlgorithm.RS256, CryptoAlgorithm.PS256}),
    ))
    result = verifier.verify(payload, signature, kid, algorithm)
    print(f"verification succeeded issuer={result.issuer} kid={result.kid} algorithm={result.algorithm.value}")


def _decode(value: str) -> bytes:
    """
    Description: Decodes one unpadded Base64URL environment value.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        value: Unpadded Base64URL text.
    Returns:
        bytes: Decoded bytes.
    """
    return base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))


if __name__ == "__main__":
    main()
