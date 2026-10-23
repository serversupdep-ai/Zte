"""Rejection/decision diagnostic engine.

Maps the *portal's own reported outcome* onto:

* the published AT&T eligibility requirements (so a rejection can be read
  against the criteria AT&T itself publishes),
* safe next steps (pay a balance, wait, click the 24-hour confirmation link,
  call support),
* structural problems with this client (endpoint drift, challenge pages,
  missing request number).

Scope guard: this engine interprets what the server told us. It does not
probe, guess, or test the server-side decision logic, and it never suggests
altered payloads, forged fields, or ways to re-frame a rejection. If a
request is rejected, the only paths forward are the ones AT&T publishes
(fix the underlying account/device condition and file a *new* request, or
contact AT&T support).
"""
from __future__ import annotations

from typing import List, Optional, Union

from .models import Decision, Diagnostic, EligibilityResult, StatusResult, SubmitResult

# Public references (stable AT&T-published pages, verified 2026-09-09).
REF_REQUIREMENTS = "https://www.att.com/deviceunlock/"
REF_SUPPORT = "https://www.att.com/support/article/smb-wireless/KM1008728/"
REF_STATUS_PAGE = "https://www.att.com/deviceunlock/status"
REF_IMEI_FINDER = "https://www.att.com/wireless/imei-finder/"
PHONE_SUPPORT = "1-800-331-0500 (dial 611 from an AT&T phone)"

Result = Union[EligibilityResult, SubmitResult, StatusResult]

PUBLISHED_REQUIREMENTS = [
    "Device purchased 60+ days ago (and not active on another AT&T account)",
    "Device paid in full - installment balance must be zero",
    "Device not reported lost, stolen, or involved in fraud",
    "Account current (no past-due balance) for current AT&T customers",
    "AT&T Prepaid: 12 months of service (Android prepaid: use the AT&T Device Unlock app)",
]


def _dx(code: str, severity: str, title: str, detail: str,
        actions: Optional[List[str]] = None,
        references: Optional[List[str]] = None) -> Diagnostic:
    return Diagnostic(
        code=code, severity=severity, title=title, detail=detail,
        actions=actions or [], references=references or [],
    )


def diagnose(result: Result, raw_text: str = "") -> List[Diagnostic]:
    """Produce the list of diagnostics for a portal result.

    ``raw_text`` is optional additional text (e.g. the full email or a saved
    HTTP body) that is scanned for extra signal.
    """
    decision = result.decision
    text = " ".join(filter(None, [getattr(result, "message", ""), raw_text]))
    findings: List[Diagnostic] = []

    # Structural findings first (about this client / the environment).
    matched = " ".join(getattr(result, "matched", []) or [])
    if "challenge_page" in matched or "blocked" in text.lower():
        findings.append(_dx(
            "DX_WAF_CHALLENGE", "warning",
            "Portal returned a bot-challenge / blocked page",
            "The request reached AT&T's edge protection instead of the unlock "
            "service. This is an environment signal (datacenter IP, missing "
            "browser fingerprint), not an eligibility result.",
            ["Run the client from your normal network and use cookie mode "
             "(export the Cookie header from a real browser session).",
             "If it persists, do the step manually in a browser and use this "
             "tool only for status lookups."],
            [REF_REQUIREMENTS],
        ))
    if "html_not_json" in matched or "endpoint may have changed" in text.lower():
        findings.append(_dx(
            "DX_ENDPOINT_DRIFT", "warning",
            "Endpoint response shape looks stale",
            "The calibrated API path returned an HTML page instead of JSON. "
            "AT&T ships portal updates regularly; the endpoint map in "
            "docs/workflow-map.md needs re-calibration.",
            ["Open the portal in a browser with developer tools, submit a "
             "throwaway/legitimate step, note the XHR path, and update the "
             "endpoint via ATT_UNLOCK_* overrides (see README).",
             "Until then, treat every non-JSON response as unknown, not as a "
             "rejection."],
            [REF_REQUIREMENTS],
        ))
    if isinstance(result, SubmitResult) and result.decision in (
        Decision.APPROVED, Decision.PENDING, Decision.MANUAL_REVIEW
    ) and not result.request_id:
        findings.append(_dx(
            "DX_NO_REQUEST_ID", "warning",
            "No request number captured from the response",
            "The portal accepted the request but the response did not contain "
            "a recognizable NUL... request number. The number is normally in "
            "the confirmation email.",
            ["Check your inbox (and spam/junk) for the AT&T unlock email and "
             "record the request number.",
             "Use `python -m att_unlock diagnose --json-file <saved-response>` "
             "on the saved raw response if it exists."],
            [REF_STATUS_PAGE],
        ))

    # Decision-specific findings.
    if decision == Decision.APPROVED:
        findings.append(_dx(
            "DX_APPROVED", "info",
            "Request approved by AT&T",
            "The portal reports the unlock was approved. For iPhones the "
            "unlock is applied remotely (no code): remove the AT&T SIM, "
            "insert another carrier's SIM, and reboot. For Android devices "
            "the unlock code and device-specific instructions arrive by "
            "email - wrong codes entered too many times can permanently "
            "block the network lock.",
            ["Complete the device-side unlock steps from the approval email.",
             "If the code was not sent, AT&T allows a new request (there is a "
             "limit on re-requests per the published docs)."],
            [REF_SUPPORT],
        ))
    elif decision == Decision.PENDING:
        findings.append(_dx(
            "DX_PENDING", "info",
            "Request is pending - normal processing window applies",
            "AT&T's published process says the portal responds within two "
            "business days (the status page is the reliable source of truth; "
            "some devices may take longer).",
            ["Check status with IMEI + request number at "
             f"{REF_STATUS_PAGE} (or `python -m att_unlock status`).",
             "Keep the request number; do not resubmit while pending."],
            [REF_STATUS_PAGE, REF_REQUIREMENTS],
        ))
    elif decision == Decision.REJECTED:
        findings.append(_dx(
            "DX_REJECTED", "error",
            "Request rejected by AT&T",
            "The portal returned a rejection. The client cannot and will not "
            "alter this outcome; the path forward is the published one: fix "
            "the underlying condition and file a new request, or ask AT&T "
            "support to explain the specific reason.",
            ["Check each published requirement against your account (see "
             "details below).",
             "Call " + PHONE_SUPPORT + " and ask for the specific rejection "
             "reason and any appeal path."],
            [REF_REQUIREMENTS, REF_SUPPORT],
        ))
        findings.append(_dx(
            "DX_REJECTED_REQUIREMENTS", "info",
            "Published eligibility requirements to check",
            "AT&T publishes these criteria; a rejection usually maps to one "
            "of them. Which one is a server-side business decision the "
            "portal does not expose.",
            [f"- {r}" for r in PUBLISHED_REQUIREMENTS],
            [REF_REQUIREMENTS, REF_SUPPORT],
        ))
    elif decision == Decision.ELIGIBILITY_FAILED:
        findings.append(_dx(
            "DX_ELIGIBILITY", "error",
            "Portal pre-check says the device is not eligible (yet)",
            "Eligibility is evaluated by AT&T from account and device records "
            "- an IMEI that is 'clean' (not reported stolen) is necessary but "
            "NOT sufficient. The published criteria the server checks against "
            "include purchase age, payment status, lost/stolen status and "
            "account standing.",
            ["Confirm the installment balance is zero (MyAT&T > device > "
             "installment plan).",
             "Confirm the bill is current and the device has been on the "
             "account 60+ days (12 months for prepaid).",
             "If everything checks out, call " + PHONE_SUPPORT + " - the "
             "portal pre-check can be out of date with account changes."],
            [REF_REQUIREMENTS, REF_SUPPORT],
        ))
    elif decision == Decision.INVALID_IMEI:
        findings.append(_dx(
            "DX_INVALID_IMEI", "error",
            "IMEI not recognized / invalid",
            "The IMEI was rejected by local validation or by the portal. Note "
            "that AT&T can only unlock devices that are locked to the AT&T "
            "network; an IMEI that was never on AT&T, or of a device from "
            "another carrier, will fail here.",
            ["Re-read the IMEI with *#06# (dual-SIM: use IMEI 1) or from "
             "Settings > About / the original box.",
             f"Use the official finder: {REF_IMEI_FINDER}",
             "If the device is an AT&T device and the IMEI is correct, the "
             "device may not be AT&T-locked or may be out of AT&T's records - "
             "ask support."],
            [REF_IMEI_FINDER, REF_SUPPORT],
        ))
    elif decision == Decision.MANUAL_REVIEW:
        findings.append(_dx(
            "DX_MANUAL_REVIEW", "warning",
            "Request needs an extra verification step (human)",
            "AT&T's published flow includes an email-confirmation step in "
            "some cases: the confirmation link in the email must be clicked "
            "within 24 hours. Military deployment cases additionally "
            "require deployment documents by email.",
            ["Open the AT&T email (check spam/junk), click the confirmation "
             "link within 24 hours.",
             "For deployment: include the requested deployment documents in "
             "the reply as instructed in the email."],
            [REF_REQUIREMENTS, REF_SUPPORT],
        ))
    elif decision == Decision.TEMPORARY_ERROR:
        findings.append(_dx(
            "DX_TEMPORARY", "warning",
            "Temporary/transport error - no decision was made",
            "The portal could not produce a decision this time (5xx, timeout, "
            "throttling, or challenge page). Nothing should be resubmitted "
            "immediately: if the previous POST actually landed, a duplicate "
            "request is possible.",
            ["Wait (minutes to a day) and retry the same step.",
             "Before resubmitting an unlock request, check the status page "
             "in a browser to make sure a request wasn't already created.",
             "If you keep hitting a challenge page, switch to cookie mode."],
            [REF_STATUS_PAGE],
        ))

    # Cross-cutting: confidence note.
    if getattr(result, "confidence", "high") == "low":
        findings.append(_dx(
            "DX_LOW_CONFIDENCE", "info",
            "Low-confidence classification",
            "The response did not contain an explicit decision field or a "
            "strong keyword; the classification is a best-effort read. Treat "
            "it as 'unknown' and verify against the status page before "
            "acting on it.",
            ["Use `python -m att_unlock status --request-id <ID> --imei <IMEI>` "
             "once you have the request number from the confirmation email."],
            [REF_STATUS_PAGE],
        ))

    return findings
