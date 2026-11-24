"""
Description: Defines stable exceptions returned by the KeyPilot Python SDK.
Author: vectorshi
Created: 2026-11-25
"""

from typing import Optional

from .enums import SdkErrorCode


class KeyPilotError(Exception):
    """
    Description: Represents a configuration, refresh, key, or verification failure.
    Author: vectorshi
    Created: 2026-11-25
    Parameters:
        code: Stable SDK error code.
        message: Diagnostic message without sensitive key material.
        cause: Optional lower-level exception.
    Returns: None.
    """

    def __init__(self, code: SdkErrorCode, message: str, cause: Optional[BaseException] = None) -> None:
        """
        Description: Initializes a KeyPilot exception.
        Author: vectorshi
        Created: 2026-11-25
        Parameters:
            code: Stable SDK error code.
            message: Diagnostic message without sensitive key material.
            cause: Optional lower-level exception.
        Returns: None.
        """
        super().__init__(f"keypilot sdk error code={int(code)}: {message}")
        self.code = code
        self.message = message
        self.cause = cause
