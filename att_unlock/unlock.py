"""Unlock-request workflow (eligibility pre-check + submission).

Replicates the *legitimate* portal workflow for a single device on the
operator's own account:

    1. validate the IMEI locally (format + Luhn warning)
    2. ensure an authenticated session (cookie mode or human-completed MFA)
    3. POST the eligibility pre-check for the IMEI
    4. only if the portal itself says the device is eligible, POST the unlock
       request
    5. parse the response: request number (NUL...), whether an email
       confirmation step is required (24-hour link, per AT&T's published
       process)

Hard rules enforced here:
* a local rate gate limits submission frequency (see HttpClient.guard_submit);
* rejected / ineligible / invalid-IMEI outcomes are **final** for this run -
  the client never retries, mutates, or "pushes" them toward approval;
* the operator must explicitly confirm the submission in the CLI (--yes) so
  that a live request is never fired accidentally during calibration.
"""
from __future__ import annotations

import logging
from typing import Optional

from .auth import AuthManager
from .client import HttpClient
from .config import Config
from .models import (
    BlockedError,
    Decision,
    EligibilityResult,
    RateLimitedLocally,
    SubmitResult,
    TransportError,
)
from .parser import (
    clean_imei,
    classify_response,
    classify_transport_error,
    extract_confirmation_url,
    extract_request_id,
    looks_like_challenge_page,
    validate_imei,
)
from .session import SessionState


class UnlockService:
    def __init__(
        self,
        config: Config,
        client: HttpClient,
        session: SessionState,
        auth: Optional[AuthManager] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        self.client = client
        self.session = session
        self.auth = auth or AuthManager(config, client, logger=logger)
        self.log = logger or logging.getLogger("att_unlock.unlock")

    # ---------------------------------------------------------- eligibility

    def check_eligibility(self, raw_imei: str, phone: Optional[str] = None) -> EligibilityResult:
        """Run the portal's own eligibility pre-check for one IMEI."""
        ok, reason = validate_imei(raw_imei)
        if not ok:
            return EligibilityResult(
                decision=Decision.INVALID_IMEI,
                eligible=False,
                imei=(raw_imei or "").strip(),
                message=reason,
                confidence="high",
                matched=["local_validation"],
            )
        imei = clean_imei(raw_imei)
        if reason != "ok":
            self.log.warning("IMEI check: %s", reason)

        self.log.info("checking eligibility for IMEI ...%s", imei[-4:])
        payload = {"imei": imei}
        if phone:
            payload["phoneNumber"] = phone

        try:
            resp = self.client.post(
                self.config.endpoints.eligibility,
                headers=self.session.headers(),
                json_body=payload,
            )
        except TransportError as err:
            cls = classify_transport_error(err)
            return EligibilityResult(
                decision=cls.decision, eligible=None, imei=imei,
                message=str(err), confidence=cls.confidence, matched=cls.matched,
            )

        if looks_like_challenge_page(resp):
            raise BlockedError(
                "eligibility endpoint returned a challenge page; use cookie "
                "mode with a browser session"
            )

        self.session.merge_cookies(resp.set_cookies)
        cls = classify_response(resp)
        eligible: Optional[bool]
        if cls.decision == Decision.APPROVED:
            eligible = True
        elif cls.decision in (Decision.ELIGIBILITY_FAILED, Decision.REJECTED,
                              Decision.INVALID_IMEI):
            eligible = False
        else:
            # PENDING / MANUAL_REVIEW / TEMPORARY_ERROR are ambiguous: the
            # submission is withheld until the pre-check is unambiguous.
            eligible = None
        return EligibilityResult(
            decision=cls.decision,
            eligible=eligible,
            imei=imei,
            message=cls.message,
            request_id=cls.request_id,
            confidence=cls.confidence,
            matched=cls.matched,
            raw={"status": resp.status, "body": resp.body[:4000]},
        )

    # -------------------------------------------------------------- submit

    def submit(
        self,
        raw_imei: str,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        is_customer: Optional[bool] = None,
        agree_to_requirements: bool = True,
    ) -> SubmitResult:
        """Full workflow: eligibility check, then submission if eligible.

        ``agree_to_requirements`` mirrors the portal's consent checkbox to the
        published eligibility requirements; the CLI only passes True after the
        operator confirms explicitly.
        """
        ok, reason = validate_imei(raw_imei)
        if not ok:
            return SubmitResult(
                decision=Decision.INVALID_IMEI, imei=(raw_imei or "").strip(),
                message=reason, confidence="high", matched=["local_validation"],
            )
        imei = clean_imei(raw_imei)
        if reason != "ok":
            self.log.warning("IMEI check: %s", reason)

        # 1) local pace gate (before any network I/O)
        self.client.guard_submit()

        # 2) session
        self.auth.ensure(self.session)

        # 3) portal's own eligibility decision
        elig = self.check_eligibility(imei, phone=phone)
        if elig.decision in (Decision.INVALID_IMEI, Decision.ELIGIBILITY_FAILED, Decision.REJECTED):
            return SubmitResult(
                decision=elig.decision,
                imei=imei,
                request_id=elig.request_id,
                message=(
                    "portal says this device is not currently eligible; the "
                    f"request was NOT submitted. {elig.message}"
                ),
                confidence=elig.confidence,
                matched=elig.matched + ["eligibility_gate"],
                raw=elig.raw,
            )
        if elig.decision == Decision.TEMPORARY_ERROR:
            return SubmitResult(
                decision=Decision.TEMPORARY_ERROR,
                imei=imei,
                message=(
                    "eligibility check could not complete (temporary error); "
                    "nothing was submitted. " + elig.message
                ),
                confidence=elig.confidence,
                matched=elig.matched + ["eligibility_gate"],
                raw=elig.raw,
            )
        if elig.eligible is not True:
            # PENDING / MANUAL_REVIEW / unknown: do not fire a real request
            # into an ambiguous state.
            return SubmitResult(
                decision=elig.decision,
                imei=imei,
                request_id=elig.request_id,
                email_confirmation_required=elig.decision == Decision.MANUAL_REVIEW,
                message=(
                    "portal pre-check returned "
                    f"'{elig.decision.value}'; submission withheld until the "
                    f"state is unambiguous. {elig.message}"
                ),
                confidence=elig.confidence,
                matched=elig.matched + ["eligibility_gate"],
                raw=elig.raw,
            )

        # 4) the portal itself said eligible -> submit
        payload = {
            "imei": imei,
            "agree": bool(agree_to_requirements),
        }
        if phone:
            payload["phoneNumber"] = phone
        if email:
            payload["email"] = email
        if is_customer is not None:
            payload["attCustomer"] = bool(is_customer)

        self.log.info("submitting unlock request for IMEI ...%s", imei[-4:])
        try:
            resp = self.client.post(
                self.config.endpoints.submit,
                headers=self.session.headers(),
                json_body=payload,
            )
        except TransportError as err:
            cls = classify_transport_error(err)
            return SubmitResult(
                decision=cls.decision, imei=imei,
                message="submission request failed at the network level (nothing "
                        f"confirmed): {err}",
                confidence=cls.confidence, matched=cls.matched,
            )

        self.client.mark_submit()
        self.session.merge_cookies(resp.set_cookies)

        if looks_like_challenge_page(resp):
            return SubmitResult(
                decision=Decision.TEMPORARY_ERROR,
                imei=imei,
                message="submission returned a challenge page; the request state "
                        "is UNKNOWN - check the status page in a browser before "
                        "retrying (do not resubmit blindly)",
                confidence="medium", matched=["challenge_page"],
                raw={"status": resp.status},
            )

        cls = classify_response(resp)
        confirmation_url = extract_confirmation_url(resp.body or "")
        request_id = extract_request_id(resp.body or "") or cls.request_id
        email_required = (
            cls.decision == Decision.MANUAL_REVIEW
            or confirmation_url is not None
            or "confirm" in (cls.message or "").lower()
        )
        return SubmitResult(
            decision=cls.decision,
            imei=imei,
            request_id=request_id,
            email_confirmation_required=email_required,
            confirmation_url=confirmation_url,
            message=cls.message,
            confidence=cls.confidence,
            matched=cls.matched,
            raw={"status": resp.status, "body": resp.body[:4000]},
        )
