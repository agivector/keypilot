"""
Description: Tests shared vectors and cache policy behavior of the KeyPilot Python SDK.
Author: vectorshi
Created: 2026-11-25
"""

import base64
import json
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Tuple, Type

from keypilot import Config, CryptoAlgorithm, FailureMode, KeyPilotError, SdkErrorCode, Verifier

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class _ServerState:
    """
    Description: Stores synchronized mutable JWKS test server state.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        body: JWKS response bytes.
        etag: Response ETag.
    Returns: None.
    """

    def __init__(self, body: bytes, etag: str) -> None:
        """
        Description: Initializes synchronized JWKS response state.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            body: JWKS response bytes.
            etag: Response ETag.
        Returns: None.
        """
        self.lock = threading.Lock()
        self.body = body
        self.etag = etag
        self.status = 200
        self.requests = 0
        self.last_if_none_match = ""

    def set(self, body: bytes, etag: str, status: int) -> None:
        """
        Description: Replaces synchronized JWKS response state.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            body: JWKS response bytes.
            etag: Response ETag.
            status: HTTP status code.
        Returns: None.
        """
        with self.lock:
            self.body = body
            self.etag = etag
            self.status = status

    def snapshot(self) -> Tuple[int, str]:
        """
        Description: Returns request counters without data races.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns:
            tuple: Request count and most recent If-None-Match value.
        """
        with self.lock:
            return self.requests, self.last_if_none_match


def _handler_type(state: _ServerState) -> Type[BaseHTTPRequestHandler]:
    """
    Description: Creates an HTTP handler bound to mutable JWKS state.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        state: Mutable synchronized server state.
    Returns:
        type: Bound HTTP request handler type.
    """

    class Handler(BaseHTTPRequestHandler):
        """
        Description: Serves synchronized JWKS responses for tests.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """

        def do_GET(self) -> None:
            """
            Description: Returns the current JWKS response or an ETag 304.
            Author: vectorshi
            Created: 2026-11-25
            Parameters: None.
            Returns: None.
            """
            with state.lock:
                state.requests += 1
                state.last_if_none_match = self.headers.get("If-None-Match", "")
                body = state.body
                etag = state.etag
                status = state.status
                if status == 200 and etag and state.last_if_none_match == etag:
                    status = 304
            self.send_response(status)
            if etag:
                self.send_header("ETag", etag)
            self.end_headers()
            if status == 200:
                self.wfile.write(body)

        def log_message(self, format_value: str, *args: object) -> None:
            """
            Description: Suppresses test HTTP access logs.
            Author: vectorshi
            Created: 2026-11-25
            Parameters:
                format_value: Log format string.
                args: Log format arguments.
            Returns: None.
            """
            return

    return Handler


class VerifierTest(unittest.TestCase):
    """
    Description: Verifies shared vectors and SDK cache behavior.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns: None.
    """

    def test_shared_signature_vectors(self) -> None:
        """
        Description: Verifies all fixed RS256 and PS256 cross-language cases.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        jwks = _read_vector("keys", "rsa-public-jwks.json")
        vectors = json.loads(_read_vector("cases", "signatures.json"))
        state, server, thread = _start_server(jwks, '"vectors-v1"')
        self.addCleanup(_stop_server, server, thread)
        verifier = _new_verifier(server, FailureMode.STRICT)
        for case in vectors["cases"]:
            with self.subTest(case=case["name"]):
                payload = _decode(case["payload_base64"])
                algorithm = CryptoAlgorithm(case["algorithm"])
                if case["expected_valid"]:
                    result = verifier.verify(payload, case["signature_base64url"], case["kid"], algorithm)
                    self.assertTrue(result.valid)
                    self.assertEqual(case["kid"], result.kid)
                    self.assertEqual(algorithm, result.algorithm)
                else:
                    with self.assertRaises(KeyPilotError) as raised:
                        verifier.verify(payload, case["signature_base64url"], case["kid"], algorithm)
                    self.assertEqual(SdkErrorCode(case["expected_error_code"]), raised.exception.code)
        self.assertGreaterEqual(state.snapshot()[0], 1)

    def test_etag_unknown_key_cooldown_and_replacement(self) -> None:
        """
        Description: Verifies ETag refresh, unknown-kid cooldown, and full replacement.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        jwks = _read_vector("keys", "rsa-public-jwks.json")
        state, server, thread = _start_server(jwks, '"v1"')
        self.addCleanup(_stop_server, server, thread)
        verifier = _new_verifier(server, FailureMode.STRICT)
        current_time = [datetime(2026, 11, 25, tzinfo=timezone.utc)]
        verifier._now = lambda: current_time[0]
        payload, signature = _valid_rs256_input()

        verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
        current_time[0] += timedelta(minutes=2)
        verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
        self.assertEqual((2, '"v1"'), state.snapshot())

        with self.assertRaises(KeyPilotError) as first_unknown:
            verifier.verify(payload, signature, "unknown-1", CryptoAlgorithm.RS256)
        self.assertEqual(SdkErrorCode.KEY_NOT_FOUND, first_unknown.exception.code)
        first_count = state.snapshot()[0]
        with self.assertRaises(KeyPilotError) as second_unknown:
            verifier.verify(payload, signature, "unknown-2", CryptoAlgorithm.RS256)
        self.assertEqual(SdkErrorCode.KEY_NOT_FOUND, second_unknown.exception.code)
        self.assertEqual(first_count, state.snapshot()[0])

        ps_only = _single_jwk(jwks, "vector-ps256-2026-01")
        state.set(ps_only, '"v2"', 200)
        current_time[0] += timedelta(minutes=2)
        verifier._ensure_usable_cache()
        self.assertIsNone(verifier._get_key("vector-rs256-2026-01"))

        state.set(_duplicate_jwks(ps_only), '"v3"', 200)
        with self.assertRaises(KeyPilotError) as duplicate:
            verifier._refresh()
        self.assertEqual(SdkErrorCode.JWKS_INVALID_RESPONSE, duplicate.exception.code)
        self.assertIsNotNone(verifier._get_key("vector-ps256-2026-01"))

    def test_failure_modes(self) -> None:
        """
        Description: Verifies STRICT and AVAILABLE stale-cache behavior.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        jwks = _read_vector("keys", "rsa-public-jwks.json")
        payload, signature = _valid_rs256_input()
        for mode in (FailureMode.STRICT, FailureMode.AVAILABLE):
            with self.subTest(mode=mode):
                state, server, thread = _start_server(jwks, f'"{mode.name.lower()}-v1"')
                try:
                    verifier = _new_verifier(server, mode)
                    current_time = [datetime(2026, 11, 25, tzinfo=timezone.utc)]
                    verifier._now = lambda: current_time[0]
                    verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                    state.set(b"", "", 503)
                    current_time[0] += timedelta(minutes=2)
                    if mode == FailureMode.STRICT:
                        with self.assertRaises(KeyPilotError) as expired:
                            verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                        self.assertEqual(SdkErrorCode.CACHE_EXPIRED, expired.exception.code)
                    else:
                        result = verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                        self.assertTrue(result.valid)
                        _wait_for_requests(state, 2)
                        current_time[0] += timedelta(minutes=2)
                        with self.assertRaises(KeyPilotError) as expired:
                            verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
                        self.assertEqual(SdkErrorCode.CACHE_EXPIRED, expired.exception.code)
                finally:
                    _stop_server(server, thread)

    def test_strict_revocation_sla_rejects_removed_cached_key(self) -> None:
        """
        Description: Verifies removal at the 60-second STRICT refresh boundary.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        jwks = _read_vector("keys", "rsa-public-jwks.json")
        state, server, thread = _start_server(jwks, '"revocation-v1"')
        self.addCleanup(_stop_server, server, thread)
        verifier = _new_verifier(server, FailureMode.STRICT)
        current_time = [datetime(2026, 11, 25, tzinfo=timezone.utc)]
        verifier._now = lambda: current_time[0]
        payload, signature = _valid_rs256_input()
        verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
        state.set(_single_jwk(jwks, "vector-ps256-2026-01"), '"revocation-v2"', 200)
        current_time[0] += timedelta(minutes=1)
        with self.assertRaises(KeyPilotError) as removed:
            verifier.verify(payload, signature, "vector-rs256-2026-01", CryptoAlgorithm.RS256)
        self.assertEqual(SdkErrorCode.KEY_NOT_FOUND, removed.exception.code)

    def test_configuration_validation(self) -> None:
        """
        Description: Verifies HTTPS enforcement and numeric enum validation.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        with self.assertRaises(KeyPilotError) as insecure:
            Config("issuer", "http://example.com/jwks.json", frozenset({CryptoAlgorithm.RS256}))
        self.assertEqual(SdkErrorCode.CONFIGURATION_ERROR, insecure.exception.code)
        with self.assertRaises(KeyPilotError) as algorithm:
            Config("issuer", "https://example.com/jwks.json", frozenset({9999}))
        self.assertEqual(SdkErrorCode.CONFIGURATION_ERROR, algorithm.exception.code)
        configuration = Config(
            "issuer",
            "https://example.com/jwks.json",
            frozenset({CryptoAlgorithm.RS256}),
        )
        self.assertEqual(timedelta(minutes=1), configuration.refresh_interval)


def _start_server(body: bytes, etag: str) -> Tuple[_ServerState, ThreadingHTTPServer, threading.Thread]:
    """
    Description: Starts a loopback JWKS server in a daemon thread.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        body: Initial JWKS response bytes.
        etag: Initial response ETag.
    Returns:
        tuple: Mutable state, HTTP server, and server thread.
    """
    state = _ServerState(body, etag)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_type(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return state, server, thread


def _stop_server(server: ThreadingHTTPServer, thread: threading.Thread) -> None:
    """
    Description: Stops and closes a loopback JWKS test server.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        server: Running HTTP server.
        thread: Server thread.
    Returns: None.
    """
    server.shutdown()
    server.server_close()
    thread.join(timeout=1)


def _new_verifier(server: ThreadingHTTPServer, mode: FailureMode) -> Verifier:
    """
    Description: Creates a verifier with short deterministic test cache values.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        server: Local JWKS HTTP server.
        mode: Cache failure policy.
    Returns:
        Verifier: Configured verifier.
    """
    return Verifier(Config(
        issuer="vector-issuer",
        jwks_url=f"http://127.0.0.1:{server.server_port}/jwks.json",
        allowed_algorithms=frozenset({CryptoAlgorithm.RS256, CryptoAlgorithm.PS256}),
        refresh_interval=timedelta(minutes=1),
        request_timeout=timedelta(seconds=1),
        unknown_kid_cooldown=timedelta(minutes=1),
        max_stale=timedelta(minutes=3),
        failure_mode=mode,
    ))


def _read_vector(directory: str, name: str) -> bytes:
    """
    Description: Reads one shared vector file from the repository root.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        directory: Vector subdirectory.
        name: Vector file name.
    Returns:
        bytes: File content.
    """
    return (_REPOSITORY_ROOT / "test-vectors" / directory / name).read_bytes()


def _decode(value: str) -> bytes:
    """
    Description: Decodes one unpadded Base64URL test value.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        value: Unpadded Base64URL text.
    Returns:
        bytes: Decoded value.
    """
    return base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))


def _valid_rs256_input() -> Tuple[bytes, bytes]:
    """
    Description: Returns payload and signature from the shared valid RS256 case.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns:
        tuple: Decoded payload and signature bytes.
    """
    vectors = json.loads(_read_vector("cases", "signatures.json"))
    case = next(item for item in vectors["cases"] if item["name"] == "rs256_valid")
    return _decode(case["payload_base64"]), _decode(case["signature_base64url"])


def _single_jwk(content: bytes, kid: str) -> bytes:
    """
    Description: Returns a JWKS document containing only the selected key.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        content: Source JWKS bytes.
        kid: Key to retain.
    Returns:
        bytes: Single-key JWKS JSON.
    """
    document = json.loads(content)
    key = next(item for item in document["keys"] if item["kid"] == kid)
    return json.dumps({"keys": [key]}).encode("utf-8")


def _duplicate_jwks(content: bytes) -> bytes:
    """
    Description: Creates an invalid JWKS containing the same kid twice.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        content: Valid single-key JWKS bytes.
    Returns:
        bytes: Invalid duplicate-key JWKS JSON.
    """
    key = json.loads(content)["keys"][0]
    return json.dumps({"keys": [key, key]}).encode("utf-8")


def _wait_for_requests(state: _ServerState, expected: int) -> None:
    """
    Description: Waits for an asynchronous refresh request to reach the test server.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        state: Mutable JWKS server state.
        expected: Minimum request count.
    Returns: None.
    Raises:
        AssertionError: Expected request count was not reached before timeout.
    """
    deadline = time.time() + 1
    while time.time() < deadline:
        if state.snapshot()[0] >= expected:
            return
        time.sleep(0.005)
    raise AssertionError(f"expected at least {expected} requests, got {state.snapshot()[0]}")


if __name__ == "__main__":
    unittest.main()
