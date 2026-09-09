"""Unlock-request status lookup.

Public, confirmed behavior: the portal's status page (att.com/deviceunlock/
status) asks for the device IMEI **and** the unlock request number from the
confirmation email (public examples show the ``NUL##########`` shape). AT&T
customers additionally receive an SMS link that checks status without the
request number; that SMS variant is outside this client's scope by design
(reading another channel's messages is a human/OSM step).

The JSON endpoint behind that form is a calibrated value (see Endpoints).
Status lookups are GETs, so bounded retries and Retry-After honoring apply -
that is normal client behavior, not rate-limit circumvention.
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, List, Optional

from .client import HttpClient
from .config import Config
from .models import BlockedError, Decision, StatusResult, TransportError
from .parser import (
    clean_imei,
    classify_response,
    classify_transport_error,
    looks_like_challenge_page,
    validate_imei,
)
from .session import SessionState

_REQUEST_ID_SHAPE_RE = re.compile(r"^NUL\d{5,15}$", re.IGNORECASE)

# Conservative defaults for the opt-in polling loop: a few checks at most,
# spaced like a human checking back over an afternoon.
DEFAULT_MAX_CHECKS = 5
DEFAULT_POLL_INTERVAL = 600.0  # 10 minutes
DEFAULT_POLL_SLEEP = time.sleep


def normalize_request_id(raw: str) -> str:
    rid = re.sub(r"[\s\-]+", "", (raw or "").strip()).upper()
    return rid


class StatusService:
    def __init__(
        self,
        config: Config,
        client: HttpClient,
        session: SessionState,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        self.client = client
        self.session = session
        self.log = logger or logging.getLogger("att_unlock.status")

    # ------------------------------------------------------------------ API

    def get_status(self, raw_imei: str, raw_request_id: str) -> StatusResult:
        """One status lookup for (IMEI, request number)."""
        ok, imei_reason = validate_imei(raw_imei)
        if not ok:
            return StatusResult(
                decision=Decision.INVALID_IMEI,
                imei=(raw_imei or "").strip(),
                message=imei_reason,
                confidence="high",
                matched=["local_validation"],
            )
        imei = clean_imei(raw_imei)

        request_id = normalize_request_id(raw_request_id)
        if not _REQUEST_ID_SHAPE_RE.match(request_id):
            self.log.warning(
                "request number %r does not match the NUL#### shape seen in "
                "public AT&T examples; querying anyway (the shape may have "
                "changed)", request_id[:4] + "..." if request_id else "<empty>"
            )
        else:
            self.log.info("status lookup for request ...%s / IMEI ...%s",
                          request_id[-4:], imei[-4:])

        url = (
            f"{self.config.endpoints.status}"
            f"?imei={imei}&requestNumber={request_id}"
        )
        try:
            resp = self.client.get(url, headers=self.session.headers())
        except TransportError as err:
            cls = classify_transport_error(err)
            return StatusResult(
                decision=cls.decision, imei=imei, request_id=request_id,
                message=str(err), confidence=cls.confidence, matched=cls.matched,
            )

        if looks_like_challenge_page(resp):
            raise BlockedError(
                "status endpoint returned a challenge page; use cookie mode "
                "with a browser session"
            )

        self.session.merge_cookies(resp.set_cookies)
        cls = classify_response(resp)
        payload = resp.json()
        updated_at = None
        if isinstance(payload, dict):
            for key in ("updatedAt", "updated", "timestamp", "lastUpdated", "date"):
                if isinstance(payload.get(key), str):
                    updated_at = payload[key]
                    break

        return StatusResult(
            decision=cls.decision,
            imei=imei,
            request_id=cls.request_id or request_id,
            message=cls.message,
            updated_at=updated_at,
            confidence=cls.confidence,
            matched=cls.matched,
            raw={"status": resp.status, "body": resp.body[:4000]},
        )

    def wait_for_decision(
        self,
        raw_imei: str,
        raw_request_id: str,
        max_checks: int = DEFAULT_MAX_CHECKS,
        interval: float = DEFAULT_POLL_INTERVAL,
        sleep: Optional[Callable[[float], None]] = None,
    ) -> List[StatusResult]:
        """Opt-in, human-paced polling. Returns every observation.

        Stops early on a terminal decision (approved / rejected /
        eligibility_failed / invalid_imei). Each check is a plain GET that
        honors server throttling; the loop can never produce more than
        ``max_checks`` requests in total.
        """
        # Default to the client's sleep so tests (and the client's clock)
        # remain the single time source; production clients use time.sleep.
        sleeper = sleep or self.client.sleep
        results: List[StatusResult] = []
        for i in range(max(1, max_checks)):
            result = self.get_status(raw_imei, raw_request_id)
            results.append(result)
            if result.decision in (
                Decision.APPROVED,
                Decision.REJECTED,
                Decision.ELIGIBILITY_FAILED,
                Decision.INVALID_IMEI,
            ):
                break
            if i < max_checks - 1:
                self.log.info("still %s; checking again in %.0fs (check %d/%d)",
                              result.decision.value, interval, i + 1, max_checks)
                sleeper(interval)
        return results
