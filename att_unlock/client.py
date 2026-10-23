"""HTTP client layer.

Design rules (deliberate, security-relevant):

* POSTs are **never retried automatically**. An unlock request is not
  idempotent; a blind retry risks a duplicate submission. Only GETs (status
  lookups) are retried, with capped exponential backoff.
* When the server answers 429/503 with ``Retry-After``, the client *honors*
  that delay (capped) and retries only idempotent GETs. There is no proxy
  rotation, no token farming, no way to "outrun" a rate limit.
* A local minimum interval between submissions (default 5 minutes) enforces a
  human pace even when the server would allow more.
* All log lines pass headers through :func:`att_unlock.config.redact_dict`.
"""
from __future__ import annotations

import http.cookiejar
import json
import logging
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .config import Config, redact_dict
from .models import ErrorCode, RateLimitedLocally, RawResponse, TransportError

DEFAULT_UA_FALLBACK = "att-unlock-client/1.0"
MAX_RETRY_AFTER = 900.0  # never sleep longer than 15 minutes per attempt


def _classify_url_error(reason: Any) -> ErrorCode:
    text = str(reason).lower()
    if "timeout" in text or "timed out" in text:
        return ErrorCode.TIMEOUT
    if "ssl" in text or "tls" in text or "certificate" in text:
        return ErrorCode.NETWORK
    return ErrorCode.NETWORK


class UrllibTransport:
    """Standard-library transport (no third-party dependencies).

    A real browser-style cookie jar is attached so session cookies captured
    from responses are replayed on subsequent calls, exactly as the portal
    expects of a returning visitor.
    """

    def __init__(self, verify_tls: bool = True, user_agent: str = DEFAULT_UA_FALLBACK):
        self.jar = http.cookiejar.CookieJar()
        handlers: List[Any] = [urllib.request.HTTPCookieProcessor(self.jar)]
        if not verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        else:
            handlers.append(urllib.request.HTTPSHandler())
        self.opener = urllib.request.build_opener(*handlers)
        self.user_agent = user_agent

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[bytes] = None,
        timeout: float = 20.0,
    ) -> RawResponse:
        req = urllib.request.Request(url, data=data, method=method.upper())
        req.add_header("User-Agent", self.user_agent)
        req.add_header("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
        for key, value in (headers or {}).items():
            req.add_header(key, value)

        started = time.monotonic()
        try:
            resp = self.opener.open(req, timeout=timeout)
            body = resp.read()
            status = int(resp.status)
            hdrs = resp.headers
        except urllib.error.HTTPError as err:  # 4xx/5xx arrive as exceptions
            try:
                body = err.read()
            except Exception:  # pragma: no cover - defensive
                body = b""
            status = int(err.code)
            hdrs = err.headers
        except (TimeoutError, urllib.error.URLError) as err:
            reason = getattr(err, "reason", err)
            code = ErrorCode.TIMEOUT if "timed out" in str(reason).lower() else ErrorCode.NETWORK
            raise TransportError(f"request to {url} failed: {reason}", code=code)
        except ssl.SSLError as err:
            raise TransportError(f"TLS failure for {url}: {err}", ErrorCode.NETWORK)
        except OSError as err:
            code = _classify_url_error(err)
            raise TransportError(f"request to {url} failed: {err}", code=code)

        header_map: Dict[str, str] = {}
        set_cookies: List[str] = []
        for key, value in (hdrs.items() if hdrs else []):
            lk = key.lower()
            if lk == "set-cookie":
                set_cookies.append(value)
            elif lk not in header_map:
                header_map[lk] = value
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:  # pragma: no cover - defensive
            text = body.decode("latin-1", "replace")
        return RawResponse(
            status=status,
            headers=header_map,
            body=text,
            url=url,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            set_cookies=set_cookies,
        )


class HttpClient:
    """High-level client used by unlock/status/auth services.

    ``transport`` is injectable for tests; ``sleep``/``now`` are injectable so
    backoff behavior is testable without real waiting.
    """

    def __init__(
        self,
        config: Config,
        transport: Optional[Any] = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
        logger: Optional[logging.Logger] = None,
    ):
        self.config = config
        self.transport = transport or UrllibTransport(
            verify_tls=config.verify_tls, user_agent=config.user_agent
        )
        self.sleep = sleep
        self.now = now
        self.log = logger or logging.getLogger("att_unlock.http")
        self._last_submit: Optional[float] = None

    # ------------------------------------------------------------------ GET

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, attempts: int = 3) -> RawResponse:
        """GET with bounded retries for transient failures and 429/503."""
        last: Optional[TransportError] = None
        for attempt in range(max(1, attempts)):
            try:
                resp = self._do("GET", url, headers, None)
            except TransportError as err:
                last = err
                if attempt < attempts - 1:
                    delay = min(8.0, 2.0 ** attempt)
                    self.log.debug("GET %s failed (%s); retrying in %.1fs", url, err.code, delay)
                    self.sleep(delay)
                    continue
                raise
            if resp.status in (429, 503) and attempt < attempts - 1:
                delay = self._retry_delay(resp)
                self.log.warning(
                    "server rate-limited/throttled GET %s (%d); sleeping %.0fs as instructed",
                    url, resp.status, delay,
                )
                self.sleep(delay)
                continue
            return resp
        assert last is not None
        raise last

    # ----------------------------------------------------------------- POST

    def post(self, url: str, headers: Optional[Dict[str, str]] = None,
             json_body: Optional[Dict[str, Any]] = None,
             data: Optional[bytes] = None) -> RawResponse:
        """POST without automatic retry (non-idempotent by design)."""
        body = data
        hdrs = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        return self._do("POST", url, hdrs, body)

    # --------------------------------------------------------------- helpers

    def _do(self, method: str, url: str,
            headers: Optional[Dict[str, str]], data: Optional[bytes]) -> RawResponse:
        self.log.debug(">> %s %s headers=%s", method, url, redact_dict(headers or {}))
        resp = self.transport.request(
            method, url, headers, data, timeout=self.config.timeout
        )
        self.log.debug("<< %s %s in %dms", resp.status, resp.url, resp.elapsed_ms)
        return resp

    def _retry_delay(self, resp: RawResponse) -> float:
        raw = resp.header("retry-after") or ""
        if raw.strip().isdigit():
            return min(float(raw), MAX_RETRY_AFTER)
        return 15.0  # conservative default when the header is absent/unparsable

    # ----------------------------------------------------- local submission gate

    def guard_submit(self) -> None:
        """Enforce the local minimum interval between submissions.

        Raises :class:`RateLimitedLocally` if a previous submission happened
        less than ``config.min_submit_interval`` seconds ago.
        """
        if self._last_submit is None:
            return
        elapsed = self.now() - self._last_submit
        wait = self.config.min_submit_interval - elapsed
        if wait > 0:
            raise RateLimitedLocally(
                f"local safety gate: {wait:.0f}s until the next submission is "
                f"allowed (minimum interval {self.config.min_submit_interval:.0f}s). "
                "Wait and retry deliberately; this gate exists to keep request "
                "volume at a human pace."
            )

    def mark_submit(self) -> None:
        self._last_submit = self.now()
