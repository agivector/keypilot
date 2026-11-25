"""
Description: Defines and validates configuration for the KeyPilot Python SDK.
Author: vectorshi
Created: 2026-11-25
"""

from dataclasses import dataclass
from datetime import timedelta
from ipaddress import ip_address
from typing import FrozenSet
from urllib.parse import urlparse

from .enums import CryptoAlgorithm, FailureMode, SdkErrorCode
from .errors import KeyPilotError


@dataclass(frozen=True)
class Config:
    """
    Description: Binds a verifier to one trusted issuer and fixed JWKS URL.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        issuer: Trusted issuer identifier.
        jwks_url: Fixed HTTPS JWKS URL; loopback HTTP is allowed for tests.
        allowed_algorithms: Non-empty numeric algorithm whitelist.
        refresh_interval: Normal cache refresh interval.
        request_timeout: JWKS HTTP timeout.
        unknown_kid_cooldown: Minimum interval between unknown-kid refreshes.
        max_stale: Maximum cache age allowed by AVAILABLE mode.
        failure_mode: STRICT or AVAILABLE numeric policy.
    Returns: None.
    """

    issuer: str
    jwks_url: str
    allowed_algorithms: FrozenSet[CryptoAlgorithm]
    refresh_interval: timedelta = timedelta(minutes=1)
    request_timeout: timedelta = timedelta(seconds=3)
    unknown_kid_cooldown: timedelta = timedelta(seconds=30)
    max_stale: timedelta = timedelta(minutes=15)
    failure_mode: FailureMode = FailureMode.STRICT

    def __post_init__(self) -> None:
        """
        Description: Normalizes text fields and rejects unsafe configuration.
        Author: vectorshi
        Created: 2026-11-25
        Parameters: None.
        Returns: None.
        Raises:
            KeyPilotError: CONFIGURATION_ERROR when any field is invalid.
        """
        issuer = self.issuer.strip()
        jwks_url = self.jwks_url.strip()
        object.__setattr__(self, "issuer", issuer)
        object.__setattr__(self, "jwks_url", jwks_url)
        if not issuer or not jwks_url:
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "issuer and jwks_url are required")
        _validate_jwks_url(jwks_url)
        if not self.allowed_algorithms:
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "allowed_algorithms is required")
        try:
            normalized_algorithms = frozenset(CryptoAlgorithm(value) for value in self.allowed_algorithms)
        except (TypeError, ValueError) as error:
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "allowed_algorithms contains an unsupported value", error) from error
        object.__setattr__(self, "allowed_algorithms", normalized_algorithms)
        try:
            failure_mode = FailureMode(self.failure_mode)
        except (TypeError, ValueError) as error:
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "failure_mode is invalid", error) from error
        object.__setattr__(self, "failure_mode", failure_mode)
        durations = (self.refresh_interval, self.request_timeout, self.unknown_kid_cooldown, self.max_stale)
        if any(duration.total_seconds() <= 0 for duration in durations):
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "duration values must be positive")
        if self.max_stale < self.refresh_interval:
            raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "max_stale must not be less than refresh_interval")


def _validate_jwks_url(raw_url: str) -> None:
    """
    Description: Enforces HTTPS except for loopback hosts used by local tests.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        raw_url: Configured JWKS URL.
    Returns: None.
    Raises:
        KeyPilotError: CONFIGURATION_ERROR when the URL is unsafe or invalid.
    """
    parsed = urlparse(raw_url)
    if not parsed.hostname:
        raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "jwks_url is invalid")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return
    raise KeyPilotError(SdkErrorCode.CONFIGURATION_ERROR, "jwks_url must use HTTPS except for localhost tests")


def _is_loopback_host(hostname: str) -> bool:
    """
    Description: Reports whether a hostname is safe for local HTTP tests.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        hostname: URL hostname without port.
    Returns:
        bool: True for localhost or loopback IP addresses.
    """
    if hostname.lower() == "localhost":
        return True
    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False
