"""att_unlock - single-account client for the AT&T Device Unlock portal.

Scope: the operator's own authorized test account and own device(s), one
request at a time, human-paced. See README.md and SECURITY.md for the full
scope statement and what this project deliberately does not do.
"""
from .models import (  # noqa: F401
    AttUnlockError,
    AuthError,
    BlockedError,
    ConfigError,
    Decision,
    Diagnostic,
    EligibilityResult,
    ErrorCode,
    RateLimitedLocally,
    RawResponse,
    StatusResult,
    SubmitResult,
    TemporaryError,
    TransportError,
)

__version__ = "1.0.0"

__all__ = [
    "AttUnlockError",
    "AuthError",
    "BlockedError",
    "ConfigError",
    "Decision",
    "Diagnostic",
    "EligibilityResult",
    "ErrorCode",
    "RateLimitedLocally",
    "RawResponse",
    "StatusResult",
    "SubmitResult",
    "TemporaryError",
    "TransportError",
    "__version__",
]
