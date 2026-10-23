"""Shared test helpers: fake transport, deterministic clock, config factory."""
from __future__ import annotations

import json
from collections import deque
from typing import Any, Dict, List, Optional

from ..client import HttpClient
from ..config import Config, Endpoints
from ..models import ErrorCode, RawResponse, TransportError
from ..parser import luhn_check

TEST_BASE_URL = "https://portal.test"


def make_config(**overrides) -> Config:
    base_url = overrides.pop("base_url", TEST_BASE_URL)
    cfg = Config(
        base_url=base_url,
        timeout=overrides.pop("timeout", 20.0),
        min_submit_interval=overrides.pop("min_submit_interval", 300.0),
        user_agent=overrides.pop("user_agent", "att-unlock-client-test"),
        verify_tls=True,
    )
    cfg.endpoints = Endpoints().resolve(cfg.base_url)
    for key, val in overrides.items():
        setattr(cfg, key, val)
    return cfg


def make_imei(base14: str = "35123456789012") -> str:
    """A deterministic, Luhn-valid 15-digit IMEI (synthetic test value)."""
    for d in range(10):
        candidate = f"{base14[:14]}{d}"
        if luhn_check(candidate):
            return candidate
    raise AssertionError("could not build a Luhn-valid IMEI")  # pragma: no cover


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.t = start
        self.slept: List[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.t += seconds


class FakeTransport:
    """Records every call and returns queued responses in order."""

    def __init__(self):
        self._responses: deque = deque()
        self.calls: List[Dict[str, Any]] = []

    def queue(self, status: int = 200, body: Any = "",
              headers: Optional[Dict[str, str]] = None,
              set_cookies: Optional[List[str]] = None) -> "FakeTransport":
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        self._responses.append({
            "status": status,
            "body": body,
            "headers": headers or {},
            "set_cookies": set_cookies or [],
        })
        return self

    def request(self, method: str, url: str,
                headers: Optional[Dict[str, str]] = None,
                data: Optional[bytes] = None,
                timeout: float = 20.0) -> RawResponse:
        self.calls.append({
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "data": data,
        })
        if not self._responses:
            raise TransportError("FakeTransport: no queued response", ErrorCode.NETWORK)
        item = self._responses.popleft()
        return RawResponse(
            status=item["status"],
            headers={k.lower(): v for k, v in item["headers"].items()},
            body=item["body"],
            url=url,
            elapsed_ms=1,
            set_cookies=list(item["set_cookies"]),
        )

    # conveniences ---------------------------------------------------------
    def post_bodies(self) -> List[Dict[str, Any]]:
        out = []
        for call in self.calls:
            if call["method"] == "POST" and call["data"]:
                out.append(json.loads(call["data"].decode("utf-8")))
        return out

    def last_url(self) -> str:
        return self.calls[-1]["url"] if self.calls else ""


def make_client(config: Optional[Config] = None,
                transport: Optional[FakeTransport] = None,
                clock: Optional[FakeClock] = None) -> tuple:
    cfg = config or make_config()
    tr = transport or FakeTransport()
    clk = clock or FakeClock()
    client = HttpClient(cfg, transport=tr, sleep=clk.sleep, now=clk.now)
    return client, tr, clk
