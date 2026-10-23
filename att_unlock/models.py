"""Core data types for the att_unlock client.

All types are plain dataclasses so results serialize trivially to JSON and
tests can construct them without any network access.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Decision(str, Enum):
    """Normalized outcomes of an AT&T unlock-portal interaction.

    These are the only states the client can know about: they are derived
    exclusively from what the portal itself returns (explicit fields or the
    human-readable text it sends back), never from assumptions about
    server-side business logic.
    """

    APPROVED = "approved"
    PENDING = "pending"
    REJECTED = "rejected"
    INVALID_IMEI = "invalid_imei"
    ELIGIBILITY_FAILED = "eligibility_failed"
    TEMPORARY_ERROR = "temporary_error"
    MANUAL_REVIEW = "manual_review"


class ErrorCode(str, Enum):
    """Transport-level failure codes."""

    NETWORK = "network_error"
    TIMEOUT = "timeout"
    HTTP_ERROR = "http_error"
    NOT_JSON = "not_json"
    BLOCKED = "blocked_or_challenge"
    RATE_LIMITED = "rate_limited"


class AttUnlockError(Exception):
    """Base class for all att_unlock errors."""


class ConfigError(AttUnlockError):
    """Missing or invalid configuration."""


class AuthError(AttUnlockError):
    """Authentication failed or session material is missing."""


class RateLimitedLocally(AttUnlockError):
    """The client's own safety interval between submissions has not elapsed."""


class BlockedError(AttUnlockError):
    """The portal returned a WAF/bot-challenge page instead of content."""


class TemporaryError(AttUnlockError):
    """Transient server-side failure (5xx, timeouts, maintenance)."""


class TransportError(AttUnlockError):
    """Network-level failure raised by a transport implementation."""

    def __init__(self, message: str, code: ErrorCode = ErrorCode.NETWORK):
        super().__init__(message)
        self.code = code


@dataclass
class RawResponse:
    """A single HTTP response, independent of the underlying transport."""

    status: int
    headers: Dict[str, str]
    body: str
    url: str
    elapsed_ms: int
    set_cookies: List[str] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    def json(self) -> Optional[Any]:
        """Parse the body as JSON; return None when the body is not JSON."""
        import json

        text = (self.body or "").strip()
        if not text or text[0] not in "{[":
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None


@dataclass
class EligibilityResult:
    """Outcome of an IMEI eligibility pre-check."""

    decision: Decision
    eligible: Optional[bool]  # None when the portal did not say either way
    imei: str
    message: str = ""
    request_id: Optional[str] = None
    confidence: str = "low"  # high | medium | low
    matched: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubmitResult:
    """Outcome of submitting an unlock request."""

    decision: Decision
    imei: str
    request_id: Optional[str] = None
    email_confirmation_required: bool = False
    confirmation_url: Optional[str] = None
    message: str = ""
    confidence: str = "low"
    matched: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StatusResult:
    """Outcome of looking up an existing unlock request."""

    decision: Decision
    imei: str
    request_id: Optional[str] = None
    message: str = ""
    updated_at: Optional[str] = None
    confidence: str = "low"
    matched: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Diagnostic:
    """One human-readable finding produced by the diagnostics engine."""

    code: str
    severity: str  # info | warning | error
    title: str
    detail: str
    actions: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "actions": list(self.actions),
            "references": list(self.references),
        }
