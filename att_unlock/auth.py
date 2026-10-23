"""Authentication for the operator's own test account.

Two modes, both strictly limited to the account the operator is authorized
to use:

* **cookie mode (default, recommended)** - reuse a session the operator
  already established in a real browser (where any MFA challenge was
  completed by a human). The raw Cookie header is supplied via
  ``ATT_UNLOCK_SESSION_COOKIE`` or ``ATT_UNLOCK_SESSION_COOKIE_FILE``.
* **login mode** - submit the account username/password from the environment
  to the (calibrated) login endpoint. If the portal demands MFA, the client
  pauses and asks the *human operator* for the one-time code on the
  terminal. MFA is never bypassed, automated, or skipped.

Secrets: username/password/cookies are held in memory only, never logged in
clear, and never written anywhere by this package.
"""
from __future__ import annotations

import getpass
import logging
import re
from typing import Callable, Optional

from .client import HttpClient
from .config import Config, redact
from .models import AuthError
from .parser import looks_like_challenge_page
from .session import SessionState, extract_csrf

MFA_MARKER_RE = re.compile(
    r"one[- ]time|verification\s+code|mfa|two[- ]factor|otp|security\s+code|2fa",
    re.IGNORECASE,
)
SUCCESS_MARKER_RE = re.compile(
    r'"success"\s*:\s*true|"authenticated"\s*:\s*true|loginComplete|dashboard',
    re.IGNORECASE,
)


class AuthManager:
    def __init__(
        self,
        config: Config,
        client: HttpClient,
        mfa_prompt: Callable[[str], str] = getpass.getpass,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        self.client = client
        self.mfa_prompt = mfa_prompt
        self.log = logger or logging.getLogger("att_unlock.auth")

    # ------------------------------------------------------------------ API

    def mode(self) -> str:
        if self.config.session_cookie:
            return "cookie"
        if self.config.username and self.config.password:
            return "login"
        return "none"

    def ensure(self, session: Optional[SessionState] = None) -> SessionState:
        """Return a session state suitable for authenticated calls.

        Raises :class:`AuthError` with actionable guidance when no usable
        session material exists.
        """
        session = session or SessionState()

        mode = self.mode()
        if mode == "cookie":
            if not session.cookie_header:
                session.cookie_header = self.config.session_cookie or ""
            self._soft_verify(session)
            return session

        if mode == "login":
            self._login_flow(session)
            return session

        raise AuthError(
            "no session material available. Either (a) log in to the portal in "
            "your browser (completing MFA as a human), copy the Cookie header "
            "of any portal request, and export it as ATT_UNLOCK_SESSION_COOKIE "
            "(cookie mode), or (b) set ATT_UNLOCK_USERNAME and "
            "ATT_UNLOCK_PASSWORD for interactive login mode. "
            f"Current mode: {mode!r}."
        )

    # ------------------------------------------------------------ internals

    def _soft_verify(self, session: SessionState) -> None:
        """Best-effort check that the session cookie is not obviously dead.

        A 403 challenge or a login-redirect does not hard-fail: session
        lifetimes vary, and the API call itself is the real test. We log a
        warning only (cookie values are never logged).
        """
        try:
            resp = self.client.get(self.config.endpoints.portal, headers=session.headers())
        except Exception as err:  # network issues surface at the API call
            self.log.warning("session soft-check skipped: %s", err)
            return
        if resp.status in (200, 301, 302, 303):
            self.log.debug("session soft-check ok (HTTP %d); cookies=%s",
                           resp.status, sorted(session.seen_cookie_names or []))
        else:
            self.log.warning(
                "session soft-check returned HTTP %d - the session cookie may "
                "be expired or the portal may be challenging non-browser "
                "clients; continuing",
                resp.status,
            )
        session.merge_cookies(resp.set_cookies)
        if not session.csrf_token:
            session.csrf_token = extract_csrf(resp.body, session.cookie_header)

    def _login_flow(self, session: SessionState) -> None:
        if not self.config.username or not self.config.password:
            raise AuthError("login mode requires ATT_UNLOCK_USERNAME and ATT_UNLOCK_PASSWORD")

        login_url = self.config.endpoints.login
        self.log.debug("GET login page %s", login_url)
        page = self.client.get(login_url)
        if looks_like_challenge_page(page):
            raise AuthError(
                "login page returned a challenge/blocked page. Complete the "
                "challenge in a normal browser and use cookie mode instead."
            )
        session.merge_cookies(page.set_cookies)
        session.csrf_token = extract_csrf(page.body, session.cookie_header)

        payload = {
            "username": self.config.username,
            "password": self.config.password,  # in-memory only; never logged
        }
        if session.csrf_token:
            payload["csrfToken"] = session.csrf_token

        resp = self.client.post(login_url, headers=session.headers(), json_body=payload)
        session.merge_cookies(resp.set_cookies)

        body = (resp.body or "")
        if MFA_MARKER_RE.search(body) or resp.status in (401, 403):
            self.log.info("MFA required - waiting for the operator to supply the one-time code")
            try:
                code = self.mfa_prompt("Enter the one-time MFA code shown to you (not stored): ")
            except (EOFError, KeyboardInterrupt) as err:
                raise AuthError(
                    "MFA is required for this account and could not be "
                    "completed interactively. Complete MFA in your browser and "
                    "use cookie mode."
                ) from err
            mfa_payload = {
                "username": self.config.username,
                "code": code,
            }
            if session.csrf_token:
                mfa_payload["csrfToken"] = session.csrf_token
            resp = self.client.post(login_url, headers=session.headers(), json_body=mfa_payload)
            session.merge_cookies(resp.set_cookies)
            body = (resp.body or "")

        if resp.status in (200, 201, 302, 303) and (
            SUCCESS_MARKER_RE.search(body) or self._auth_cookie_present(resp.set_cookies)
        ):
            self.log.info("login successful (HTTP %d); session established", resp.status)
            return

        raise AuthError(
            "login did not complete (HTTP "
            f"{resp.status}). {self._safe_failure_hint(body)}. Login endpoints "
            "are calibrated values; verify them in an authorized environment, "
            "or use cookie mode with a session you created in a browser."
        )

    @staticmethod
    def _auth_cookie_present(set_cookies: list) -> bool:
        auth_names = ("jsessionid", "sid", "session", "att_session", "auth", "token")
        for header in set_cookies:
            name = header.split(";", 1)[0].split("=", 1)[0].lower()
            if any(name.endswith(a) for a in auth_names):
                return True
        return False

    @staticmethod
    def _safe_failure_hint(body: str) -> str:
        """A hint that never echoes credentials or long server payloads."""
        snippet = " ".join((body or "").split())[:200]
        return f"Server response snippet: {snippet}"
