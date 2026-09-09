"""Session and CSRF token handling.

The portal is a session-cookie web app. This module:

* parses a raw ``Cookie:`` header into name/value pairs,
* extracts candidate CSRF tokens from a page body (meta tag, embedded JSON,
  or a dedicated anti-forgery cookie),
* keeps a small :class:`SessionState` object that carries the cookie header
  and the current CSRF token between steps of the workflow.

CSRF token *values* are treated as sensitive: they are never logged in full.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

META_CSRF_RE = re.compile(
    r'<meta[^>]+name=["\'](?:csrf-token|_csrf|csrfToken|XSRF-TOKEN)["\'][^>]+'
    r'content=["\']([^"\']+)',
    re.IGNORECASE,
)
META_CSRF_RE2 = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\'](?:csrf-token|_csrf|csrfToken)["\']',
    re.IGNORECASE,
)
JSON_CSRF_RE = re.compile(
    r'["\'](?:csrfToken|_csrf|csrf_token|x-csrf-token)["\']\s*:\s*["\']([^"\']{8,128})["\']',
    re.IGNORECASE,
)
_COOKIE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}=")


@dataclass
class SessionState:
    """Everything the client needs to identify the current browser session."""

    cookie_header: str = ""
    csrf_token: Optional[str] = None
    # Names (not values) of cookies we have seen - safe to display.
    seen_cookie_names: List[str] = field(default_factory=list)

    @property
    def authenticated(self) -> bool:
        return bool(self.cookie_header.strip())

    def cookies(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in self.cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                out[name.strip()] = value.strip()
        return out

    def headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.cookie_header.strip():
            headers["Cookie"] = self.cookie_header.strip()
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
            headers["X-XSRF-TOKEN"] = self.csrf_token
        return headers

    def merge_cookies(self, set_cookie_headers: List[str]) -> None:
        """Fold Set-Cookie headers from a response into our cookie header
        (mirrors what a browser does for first-party cookies)."""
        existing = self.cookies()
        for header in set_cookie_headers or []:
            pair = header.split(";", 1)[0].strip()
            if not _COOKIE_NAME_RE.match(pair):
                continue
            name, _, value = pair.partition("=")
            # Treat "name=; expires=..." (empty value) as a deletion.
            if value == "":
                existing.pop(name.strip(), None)
            else:
                existing[name.strip()] = value
        if existing:
            self.cookie_header = "; ".join(f"{k}={v}" for k, v in existing.items())
        self.seen_cookie_names = sorted(set(self.seen_cookie_names) | set(existing))


def parse_cookie_header(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            out[name.strip()] = value.strip()
    return out


def extract_csrf(html: str, cookie_header: str = "") -> Optional[str]:
    """Best-effort CSRF token extraction from a served page.

    Order: anti-forgery cookie, <meta> tag, embedded JSON config. Returns
    None when nothing looks like a token; the caller decides whether that is
    acceptable (some portals ship the token only in the JSON API response).
    """
    cookies = parse_cookie_header(cookie_header)
    for name in ("XSRF-TOKEN", "_csrf", "csrf_token", "CSRF-TOKEN"):
        if name in cookies and cookies[name]:
            return cookies[name]

    for rx in (META_CSRF_RE, META_CSRF_RE2, JSON_CSRF_RE):
        m = rx.search(html or "")
        if m:
            return m.group(1)
    return None
