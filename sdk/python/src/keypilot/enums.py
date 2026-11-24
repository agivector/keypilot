"""
Description: Defines stable numeric enums exposed by the KeyPilot Python SDK.
Author: vectorshi
Created: 2026-11-25
"""

from enum import IntEnum


class CryptoAlgorithm(IntEnum):
    """
    Description: Identifies a supported signature verification algorithm.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns: None.
    """

    RS256 = 1001
    PS256 = 1002


class FailureMode(IntEnum):
    """
    Description: Controls stale-cache behavior when JWKS refresh fails.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns: None.
    """

    STRICT = 1
    AVAILABLE = 2


class SdkErrorCode(IntEnum):
    """
    Description: Identifies a stable SDK failure category.
    Author: vectorshi
    Created: 2026-11-25
    Parameters: None.
    Returns: None.
    """

    INVALID_ARGUMENT = 6001
    ALGORITHM_NOT_ALLOWED = 6002
    KEY_NOT_FOUND = 6003
    KEY_INVALID = 6004
    SIGNATURE_INVALID = 6005
    JWKS_UNAVAILABLE = 6006
    JWKS_INVALID_RESPONSE = 6007
    CACHE_EXPIRED = 6008
    CONFIGURATION_ERROR = 6009
    INTERNAL_ERROR = 6999
