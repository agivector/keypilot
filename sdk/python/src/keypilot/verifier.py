"""
Description: Provides cached RS256 and PS256 verification for one trusted issuer.
Author: vectorshi
Created: 2026-11-25
"""

import base64
import binascii
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet, Optional, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .config import Config
from .enums import CryptoAlgorithm, FailureMode, SdkErrorCode
from .errors import KeyPilotError

_MAX_JWKS_RESPONSE_BYTES = 1024 * 1024
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})


@dataclass(frozen=True)
class VerificationResult:
    """
    Description: Describes a successful local signature verification.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        valid: Always True for a returned result.
        issuer: Configured trusted issuer.
        kid: Actual key identifier.
        algorithm: Actual numeric signature algorithm.
    Returns: None.
    """

    valid: bool
    issuer: str
    kid: str
    algorithm: CryptoAlgorithm


@dataclass(frozen=True)
class _CachedKey:
    """
    Description: Stores one validated RSA public key and declared algorithm.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        public_key: Constructed RSA public key.
        algorithm: Numeric JWK algorithm.
    Returns: None.
    """

    public_key: rsa.RSAPublicKey
    algorithm: CryptoAlgorithm


class Verifier:
    """
    Description: Manages one issuer-scoped JWKS cache and verifies signatures locally.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        config: Validated trusted issuer and cache configuration.
    Returns: None.
    """

    def __init__(self, config: Config) -> None:
        """
        Description: Initializes an empty verifier with lazy first refresh.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            config: Validated trusted issuer and cache configuration.
        Returns: None.
        """
        if not isinstance(config, Config):
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "config must be a Config instance")
        self._config = config
        self._cache_lock = threading.RLock()
        self._keys: Dict[str, _CachedKey] = {}
        self._etag = ""
        self._refresh_time: Optional[datetime] = None
        self._refresh_condition = threading.Condition(threading.Lock())
        self._refreshing = False
        self._refresh_error: Optional[KeyPilotError] = None
        self._unknown_lock = threading.Lock()
        self._last_unknown_refresh: Optional[datetime] = None
        self._now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)

    def verify(
        self,
        payload: bytes,
        signature: Union[bytes, str],
        kid: str,
        algorithm: CryptoAlgorithm,
    ) -> VerificationResult:
        """
        Description: Verifies exact payload bytes with a raw or Base64URL RSA signature.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            payload: Exact original business payload bytes.
            signature: Raw signature bytes or unpadded Base64URL text.
            kid: Trusted issuer key identifier.
            algorithm: Declared numeric signature algorithm.
        Returns:
            VerificationResult: Successful verification details with valid=True.
        Raises:
            KeyPilotError: Stable SDK error for input, refresh, key, or signature failure.
        """
        if not isinstance(payload, bytes) or not payload or not isinstance(kid, str) or not kid.strip():
            raise KeyPilotError(SdkErrorCode.INVALID_ARGUMENT, "payload and kid are required")
        signature_bytes = _decode_signature(signature)
        try:
            normalized_algorithm = CryptoAlgorithm(algorithm)
        except (TypeError, ValueError) as error:
            raise KeyPilotError(SdkErrorCode.ALGORITHM_NOT_ALLOWED, "algorithm is not supported", error) from error
        if normalized_algorithm not in self._config.allowed_algorithms:
            raise KeyPilotError(SdkErrorCode.ALGORITHM_NOT_ALLOWED, "algorithm is not allowed")
        refreshed = self._ensure_usable_cache()
        cached_key = self._get_key(kid)
        if cached_key is None and not refreshed:
            self._refresh_for_unknown_key()
            cached_key = self._get_key(kid)
        if cached_key is None:
            raise KeyPilotError(SdkErrorCode.KEY_NOT_FOUND, "kid was not found in the trusted JWKS")
        if cached_key.algorithm != normalized_algorithm:
            raise KeyPilotError(SdkErrorCode.KEY_INVALID, "JWK algorithm does not match requested algorithm")
        _verify_rsa(payload, signature_bytes, cached_key.public_key, normalized_algorithm)
        return VerificationResult(True, self._config.issuer, kid, normalized_algorithm)

    def _ensure_usable_cache(self) -> bool:
        """
        Description: Applies STRICT or AVAILABLE refresh policy before key lookup.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns:
            bool: True when this call completed a synchronous refresh.
        Raises:
            KeyPilotError: Initial refresh error or CACHE_EXPIRED for stale-cache failure.
        """
        with self._cache_lock:
            refresh_time = self._refresh_time
        if refresh_time is None:
            self._refresh()
            return True
        age = self._now() - refresh_time
        if age < self._config.refresh_interval:
            return False
        if self._config.failure_mode == FailureMode.STRICT or age > self._config.max_stale:
            try:
                self._refresh()
            except KeyPilotError as error:
                raise KeyPilotError(
                    SdkErrorCode.CACHE_EXPIRED,
                    "cached JWKS is outside the allowed refresh window",
                    error,
                ) from error
            return True
        self._start_async_refresh()
        return False

    def _start_async_refresh(self) -> None:
        """
        Description: Starts one daemon refresh for AVAILABLE mode without blocking verification.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        with self._refresh_condition:
            if self._refreshing:
                return
        thread = threading.Thread(target=self._ignore_async_refresh_error, daemon=True)
        thread.start()

    def _ignore_async_refresh_error(self) -> None:
        """
        Description: Runs a background refresh while preserving the last valid cache on failure.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        """
        try:
            self._refresh()
        except KeyPilotError:
            return

    def _refresh_for_unknown_key(self) -> None:
        """
        Description: Performs at most one immediate unknown-kid refresh per cooldown window.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        Raises:
            KeyPilotError: JWKS refresh failure.
        """
        now = self._now()
        with self._unknown_lock:
            if (
                self._last_unknown_refresh is not None
                and now - self._last_unknown_refresh < self._config.unknown_kid_cooldown
            ):
                return
            self._last_unknown_refresh = now
        self._refresh()

    def _refresh(self) -> None:
        """
        Description: Coalesces concurrent requests and atomically applies a valid JWKS snapshot.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        Raises:
            KeyPilotError: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
        """
        with self._refresh_condition:
            if self._refreshing:
                while self._refreshing:
                    self._refresh_condition.wait()
                if self._refresh_error is not None:
                    raise self._refresh_error
                return
            self._refreshing = True
        error: Optional[KeyPilotError] = None
        try:
            with self._cache_lock:
                etag = self._etag
                initialized = self._refresh_time is not None
            keys, response_etag, not_modified = self._fetch_jwks(etag)
            now = self._now()
            with self._cache_lock:
                if not_modified:
                    if not initialized:
                        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "received 304 before a valid JWKS was cached")
                    self._refresh_time = now
                else:
                    self._keys = keys
                    self._etag = response_etag
                    self._refresh_time = now
        except KeyPilotError as caught:
            error = caught
        finally:
            with self._refresh_condition:
                self._refresh_error = error
                self._refreshing = False
                self._refresh_condition.notify_all()
        if error is not None:
            raise error

    def _fetch_jwks(self, etag: str) -> Tuple[Dict[str, _CachedKey], str, bool]:
        """
        Description: Retrieves and validates one complete JWKS response.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            etag: Optional ETag from the current cache.
        Returns:
            tuple: Validated key map, response ETag, and not-modified flag.
        Raises:
            KeyPilotError: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
        """
        request = Request(self._config.jwks_url, method="GET")
        if etag:
            request.add_header("If-None-Match", etag)
        try:
            with urlopen(request, timeout=self._config.request_timeout.total_seconds()) as response:
                content = response.read(_MAX_JWKS_RESPONSE_BYTES + 1)
                if len(content) > _MAX_JWKS_RESPONSE_BYTES:
                    raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS response exceeds size limit")
                return _parse_jwks(content, self._config.allowed_algorithms), response.headers.get("ETag", ""), False
        except HTTPError as error:
            if error.code == 304:
                return {}, etag, True
            raise KeyPilotError(SdkErrorCode.JWKS_UNAVAILABLE, f"JWKS endpoint returned status {error.code}", error) from error
        except (URLError, TimeoutError, OSError) as error:
            raise KeyPilotError(SdkErrorCode.JWKS_UNAVAILABLE, "request JWKS failed", error) from error

    def _get_key(self, kid: str) -> Optional[_CachedKey]:
        """
        Description: Returns one cached key by identifier.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            kid: JWK key identifier.
        Returns:
            Optional[_CachedKey]: Cached key or None.
        """
        with self._cache_lock:
            return self._keys.get(kid)


def _decode_signature(signature: Union[bytes, str]) -> bytes:
    """
    Description: Normalizes raw bytes or unpadded Base64URL signature input.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        signature: Raw signature bytes or unpadded Base64URL text.
    Returns:
        bytes: Raw RSA signature bytes.
    Raises:
        KeyPilotError: INVALID_ARGUMENT when input or encoding is invalid.
    """
    if isinstance(signature, bytes):
        if not signature:
            raise KeyPilotError(SdkErrorCode.INVALID_ARGUMENT, "signature is required")
        return signature
    if not isinstance(signature, str) or not signature:
        raise KeyPilotError(SdkErrorCode.INVALID_ARGUMENT, "signature is required")
    try:
        decoded = _base64url_decode(signature)
    except (binascii.Error, ValueError) as error:
        raise KeyPilotError(SdkErrorCode.INVALID_ARGUMENT, "signature is not valid Base64URL", error) from error
    if not decoded:
        raise KeyPilotError(SdkErrorCode.INVALID_ARGUMENT, "signature is required")
    return decoded


def _parse_jwks(content: bytes, allowed_algorithms: FrozenSet[CryptoAlgorithm]) -> Dict[str, _CachedKey]:
    """
    Description: Validates every JWK before returning an atomic replacement set.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        content: Raw JWKS JSON bytes.
        allowed_algorithms: Configured numeric algorithm whitelist.
    Returns:
        dict: Complete validated key map.
    Raises:
        KeyPilotError: JWKS_INVALID_RESPONSE when any key is invalid.
    """
    try:
        document = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS JSON is invalid", error) from error
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS keys is missing or invalid")
    keys: Dict[str, _CachedKey] = {}
    for jwk in document["keys"]:
        if not isinstance(jwk, dict):
            raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK entry must be an object")
        kid, cached_key = _parse_jwk(jwk, allowed_algorithms)
        if kid in keys:
            raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWKS contains duplicate kid")
        keys[kid] = cached_key
    return keys


def _parse_jwk(jwk: dict, allowed_algorithms: FrozenSet[CryptoAlgorithm]) -> Tuple[str, _CachedKey]:
    """
    Description: Validates one RSA public JWK and constructs its public key.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        jwk: Parsed JWK object.
        allowed_algorithms: Configured numeric algorithm whitelist.
    Returns:
        tuple: Key identifier and validated cached key.
    Raises:
        KeyPilotError: JWKS_INVALID_RESPONSE when validation fails.
    """
    kid = jwk.get("kid")
    if jwk.get("kty") != "RSA" or jwk.get("use") != "sig" or not isinstance(kid, str) or not kid.strip() or kid != kid.strip():
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK kty, use, or kid is invalid")
    if _PRIVATE_JWK_FIELDS.intersection(jwk):
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "private RSA JWK fields are not allowed")
    algorithm = _algorithm_from_jwk(jwk.get("alg"))
    if algorithm not in allowed_algorithms:
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK algorithm is not allowed by verifier configuration")
    try:
        modulus = int.from_bytes(_base64url_decode(jwk.get("n", "")), "big")
        exponent = int.from_bytes(_base64url_decode(jwk.get("e", "")), "big")
        if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
            raise ValueError("invalid RSA parameters")
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except (TypeError, ValueError, binascii.Error) as error:
        raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK RSA parameters are invalid", error) from error
    return kid, _CachedKey(public_key, algorithm)


def _algorithm_from_jwk(value: object) -> CryptoAlgorithm:
    """
    Description: Maps a standard JWK algorithm string to a numeric enum.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        value: Standard JWK alg field.
    Returns:
        CryptoAlgorithm: Mapped numeric algorithm.
    Raises:
        KeyPilotError: JWKS_INVALID_RESPONSE for unsupported values.
    """
    if value == "RS256":
        return CryptoAlgorithm.RS256
    if value == "PS256":
        return CryptoAlgorithm.PS256
    raise KeyPilotError(SdkErrorCode.JWKS_INVALID_RESPONSE, "JWK algorithm is unsupported")


def _base64url_decode(value: str) -> bytes:
    """
    Description: Decodes padded or unpadded Base64URL text with strict alphabet checks.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        value: Base64URL text.
    Returns:
        bytes: Decoded bytes.
    Raises:
        ValueError: Input is not a string.
        binascii.Error: Encoding is invalid.
    """
    if not isinstance(value, str):
        raise ValueError("Base64URL value must be text")
    padding_size = (-len(value)) % 4
    return base64.b64decode(value + ("=" * padding_size), altchars=b"-_", validate=True)


def _verify_rsa(
    payload: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
    algorithm: CryptoAlgorithm,
) -> None:
    """
    Description: Performs RS256 or PS256 verification over exact payload bytes.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        payload: Exact original business payload bytes.
        signature: Raw RSA signature bytes.
        public_key: Validated RSA public key.
        algorithm: Requested numeric signature algorithm.
    Returns: None.
    Raises:
        KeyPilotError: SIGNATURE_INVALID or ALGORITHM_NOT_ALLOWED.
    """
    if algorithm == CryptoAlgorithm.RS256:
        verification_padding = padding.PKCS1v15()
    elif algorithm == CryptoAlgorithm.PS256:
        verification_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    else:
        raise KeyPilotError(SdkErrorCode.ALGORITHM_NOT_ALLOWED, "algorithm is not supported")
    try:
        public_key.verify(signature, payload, verification_padding, hashes.SHA256())
    except InvalidSignature as error:
        raise KeyPilotError(SdkErrorCode.SIGNATURE_INVALID, "signature verification failed", error) from error
