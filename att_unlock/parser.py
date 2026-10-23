"""IMEI validation and response parsing/classification.

The classifier maps *what the portal sends back* onto the seven normalized
:class:`~att_unlock.models.Decision` values. It works on two inputs:

1. structured JSON (explicit status fields, highest confidence),
2. human-readable text (keyword rules, medium confidence).

It deliberately does not attempt to infer or reverse-engineer the
server-side decision logic; it only reports what the server chose to say.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Decision, ErrorCode, RawResponse

# ---------------------------------------------------------------------------
# IMEI validation
# ---------------------------------------------------------------------------

_IMEI_DIGITS_RE = re.compile(r"^\d{15}$")


def clean_imei(raw: str) -> str:
    """Strip separators (spaces, dashes, colons) commonly pasted from *#06#."""
    return re.sub(r"[\s\-:]+", "", (raw or "").strip())


def luhn_check(imei: str) -> bool:
    """Standard Luhn checksum (IMEI uses the Luhn algorithm on 15 digits)."""
    if not _IMEI_DIGITS_RE.match(imei):
        return False
    total = 0
    for i, ch in enumerate(reversed(imei)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_imei(raw: str) -> Tuple[bool, str]:
    """Return (ok, reason).

    * Hard failure: not exactly 15 digits after cleaning.
    * Soft warning (ok=True): Luhn checksum mismatch. A small number of
      legitimate devices carry non-Luhn IMEIs, so this never blocks a request
      - the portal is always the final word - but it is surfaced to the user.
    """
    imei = clean_imei(raw)
    if not imei:
        return False, "no IMEI supplied"
    if not _IMEI_DIGITS_RE.match(imei):
        return (
            False,
            f"IMEI must be exactly 15 digits (got {len(imei)} characters after "
            "cleaning). Dial *#06# on the device or check Settings > About.",
        )
    if not luhn_check(imei):
        return (
            True,
            "warning: IMEI fails the Luhn checksum - double-check the digits "
            "(common with hand-entered IMEIs); continuing anyway",
        )
    return True, "ok"


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

# Public examples show request numbers like NUL followed by digits.
REQUEST_ID_RE = re.compile(r"\bNUL\s?\d{5,15}\b", re.IGNORECASE)
CONFIRM_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+?(?:confirm|verify|verifyrequest|emailconfirm)[^\s\"'<>]*",
    re.IGNORECASE,
)
CHALLENGE_MARKERS = (
    "unusual traffic",
    "are you a robot",
    "verify you are human",
    "enable javascript and cookies",
    "access denied",
    "cf-challenge",
    "akamai",
    "request blocked",
)


def extract_request_id(text: str) -> Optional[str]:
    m = REQUEST_ID_RE.search(text or "")
    return m.group(0).replace(" ", "").upper() if m else None


def extract_confirmation_url(text: str) -> Optional[str]:
    m = CONFIRM_URL_RE.search(text or "")
    return m.group(0) if m else None


def looks_like_challenge_page(resp: RawResponse) -> bool:
    if resp.status in (403, 429, 503) or resp.status >= 500:
        body = (resp.body or "").lower()
        return any(marker in body for marker in CHALLENGE_MARKERS)
    return False


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass
class Classification:
    decision: Decision
    message: str
    request_id: Optional[str] = None
    confidence: str = "low"  # high | medium | low
    matched: List[str] = field(default_factory=list)


_STATUS_KEY_CANDIDATES = (
    "status", "state", "result", "decision",
    "unlockstatus", "requeststatus", "eligibilitystatus",
)
_STATUS_VALUE_MAP: Dict[str, Decision] = {
    "approved": Decision.APPROVED,
    "unlockapproved": Decision.APPROVED,
    "completed": Decision.APPROVED,
    "completed_unlock": Decision.APPROVED,
    "success": Decision.APPROVED,
    "pending": Decision.PENDING,
    "in_process": Decision.PENDING,
    "processing": Decision.PENDING,
    "submitted": Decision.PENDING,
    "received": Decision.PENDING,
    "queued": Decision.PENDING,
    "rejected": Decision.REJECTED,
    "denied": Decision.REJECTED,
    "notapproved": Decision.REJECTED,
    "canceled": Decision.REJECTED,
    "cancelled": Decision.REJECTED,
    "under_review": Decision.MANUAL_REVIEW,
    "manual_review": Decision.MANUAL_REVIEW,
    "review": Decision.MANUAL_REVIEW,
    "action_required": Decision.MANUAL_REVIEW,
    "ineligible": Decision.ELIGIBILITY_FAILED,
    "noteligible": Decision.ELIGIBILITY_FAILED,
    "eligibilityfailed": Decision.ELIGIBILITY_FAILED,
    "invalidimei": Decision.INVALID_IMEI,
    "imeinotfound": Decision.INVALID_IMEI,
    "notfound": Decision.INVALID_IMEI,
    "unknownimei": Decision.INVALID_IMEI,
    "error": Decision.TEMPORARY_ERROR,
    "failed": Decision.TEMPORARY_ERROR,
    "timeout": Decision.TEMPORARY_ERROR,
    "maintenance": Decision.TEMPORARY_ERROR,
}


def _norm_status(value: str) -> str:
    return value.strip().lower().replace(" ", "").replace("-", "").replace("_", "")


_STATUS_VALUE_MAP_NORM: Dict[str, Decision] = {
    _norm_status(k): v for k, v in _STATUS_VALUE_MAP.items()
}

# Text keyword rules, in precedence order (earlier rules win).
_TEXT_RULES: List[Tuple[str, Decision]] = [
    (r"invalid\s+imei|imei\s+(number\s+)?(is\s+)?(not|no)\s+(found|valid|recognized|matching)|unrecognized\s+imei", Decision.INVALID_IMEI),
    (r"not\s+eligible|ineligib|does\s+not\s+meet|doesn'?t\s+meet|eligibility\s+(requirements|failed|not\s+met)|unable\s+to\s+unlock|cannot\s+unlock|not\s+be\s+able\s+to\s+unlock", Decision.ELIGIBILITY_FAILED),
    (r"\brejected\b|\bdenied\b|request\s+was\s+not\s+approved|not\s+approved", Decision.REJECTED),
    (r"manual\s+review|email\s+confirmation|confirm(?:ation)?\s+(link|email)|click\s+(the|this)\s+link|link in the email|additional\s+verification|action\s+required", Decision.MANUAL_REVIEW),
    (r"\bpending\b|in\s+progress|being\s+processed|will\s+be\s+processed|processing\s+your\s+request|within\s+\d+\s+business\s+days", Decision.PENDING),
    (r"\bapproved\b|has\s+been\s+approved|unlock\s+code\s+(sent|attached)|unlock\s+complete", Decision.APPROVED),
]
_TEXT_COMPILED = [(re.compile(rx, re.IGNORECASE), dec) for rx, dec in _TEXT_RULES]

_MESSAGE_KEYS = ("message", "reason", "detail", "details", "statusMessage", "text")


def _flatten(payload: Any) -> Dict[str, Any]:
    """Shallow-unwrap common envelopes like {"data": {...}, "status": ...}."""
    if not isinstance(payload, dict):
        return {}
    out = dict(payload)
    inner = payload.get("data") or payload.get("result") or payload.get("payload")
    if isinstance(inner, dict):
        for k, v in inner.items():
            out.setdefault(k, v)
    return out


def _status_from_fields(payload: Dict[str, Any]) -> Optional[Decision]:
    flat = _flatten(payload)
    for key in _STATUS_KEY_CANDIDATES:
        for k, v in flat.items():
            if key in k.lower() and isinstance(v, str) and v:
                dec = _STATUS_VALUE_MAP_NORM.get(_norm_status(v))
                if dec is not None:
                    return dec
    return None


def _text_from_payload(payload: Dict[str, Any]) -> str:
    flat = _flatten(payload)
    parts = []
    for key in _MESSAGE_KEYS:
        for k, v in flat.items():
            if k.lower() == key.lower() and isinstance(v, str) and v.strip():
                parts.append(v)
    # Fall back to any string leaf so keyword rules still have material.
    if not parts:
        for v in flat.values():
            if isinstance(v, str) and v.strip():
                parts.append(v)
    return " ".join(parts)


def classify_response(resp: RawResponse, *, error_code: Optional[ErrorCode] = None) -> Classification:
    """Classify a raw portal response into one of the seven decisions.

    Precedence:
      transport/HTTP-level failure > explicit status field > text keywords
      > structural fallback (page instead of API response => temporary error).
    """
    request_id = extract_request_id(resp.body or "")

    if error_code is not None:
        if error_code == ErrorCode.RATE_LIMITED:
            return Classification(
                Decision.TEMPORARY_ERROR,
                "server is rate-limiting; the client honored Retry-After and "
                "will back off automatically",
                request_id=request_id, confidence="high", matched=["rate_limited"],
            )
        if error_code == ErrorCode.BLOCKED:
            return Classification(
                Decision.TEMPORARY_ERROR,
                "portal returned a WAF/bot-challenge page instead of content",
                request_id=request_id, confidence="medium", matched=["challenge_page"],
            )
        return Classification(
            Decision.TEMPORARY_ERROR,
            f"transport failure: {error_code.value}",
            request_id=request_id, confidence="high", matched=[error_code.value],
        )

    if resp.status >= 500:
        return Classification(
            Decision.TEMPORARY_ERROR,
            f"server error HTTP {resp.status} - transient; retry later",
            request_id=request_id, confidence="high", matched=[f"http_{resp.status}"],
        )
    if resp.status in (429, 503):
        return Classification(
            Decision.TEMPORARY_ERROR,
            f"throttled HTTP {resp.status} - the client will honor Retry-After",
            request_id=request_id, confidence="high", matched=[f"http_{resp.status}"],
        )
    if looks_like_challenge_page(resp):
        return Classification(
            Decision.TEMPORARY_ERROR,
            "portal returned a challenge/blocked page (bot protection or IP "
            "policy) - use a normal browser session and cookie-based auth",
            request_id=request_id, confidence="medium", matched=["challenge_page"],
        )

    payload = resp.json()
    if isinstance(payload, (dict, list)):
        field_decision = _status_from_fields(payload) if isinstance(payload, dict) else None
        text = _text_from_payload(payload) if isinstance(payload, dict) else " ".join(
            v for v in payload if isinstance(v, str)
        )
        if field_decision is not None:
            return Classification(
                field_decision, text.strip(), request_id=request_id,
                confidence="high", matched=["status_field"],
            )
        return _classify_text(text, request_id)

    body = (resp.body or "").strip()
    if body[:1] in ("<",) or body.lower().startswith("<!doctype"):
        if 400 <= resp.status < 500:
            return Classification(
                Decision.TEMPORARY_ERROR,
                f"HTTP {resp.status} with an HTML page (endpoint may have "
                "changed or the API path is not calibrated)",
                request_id=request_id, confidence="medium",
                matched=["html_on_error"],
            )
        return Classification(
            Decision.TEMPORARY_ERROR,
            "portal returned an HTML page where a JSON response was expected - "
            "the API endpoint is probably not calibrated for this deployment",
            request_id=request_id, confidence="medium", matched=["html_not_json"],
        )

    if resp.status >= 400:
        return Classification(
            Decision.TEMPORARY_ERROR,
            f"HTTP {resp.status} with unparseable body",
            request_id=request_id, confidence="medium", matched=[f"http_{resp.status}"],
        )

    return _classify_text(body, request_id)


def _classify_text(text: str, request_id: Optional[str]) -> Classification:
    if not text or not text.strip():
        return Classification(
            Decision.TEMPORARY_ERROR,
            "empty response body - treating as a temporary error",
            request_id=request_id, confidence="low", matched=["empty_body"],
        )
    for rx, decision in _TEXT_COMPILED:
        m = rx.search(text)
        if m:
            return Classification(
                decision, text.strip(), request_id=request_id,
                confidence="medium", matched=[m.group(0)],
            )
    return Classification(
        Decision.PENDING,
        "no explicit decision found in response; assuming the request was "
        "accepted and is pending - verify via the status lookup",
        request_id=request_id, confidence="low", matched=["default_pending"],
    )


def classify_transport_error(err: Any) -> Classification:
    """Classification for a TransportError that never produced a response."""
    code = getattr(err, "code", ErrorCode.NETWORK)
    if isinstance(code, ErrorCode) and code == ErrorCode.TIMEOUT:
        return Classification(
            Decision.TEMPORARY_ERROR, f"request timed out: {err}",
            confidence="high", matched=["timeout"],
        )
    return Classification(
        Decision.TEMPORARY_ERROR, f"network failure: {err}",
        confidence="high", matched=[code.value if isinstance(code, ErrorCode) else "network_error"],
    )
