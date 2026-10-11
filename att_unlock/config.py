"""Configuration loading and secret handling.

Secrets are only ever read from the process environment or an explicit local
secrets file (KEY=VALUE lines). They are never written to disk by this
package, never included in log output, and never embedded in exceptions.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import ConfigError

# Host root. Endpoint paths (Endpoints) carry the /deviceunlock/ prefix.
DEFAULT_BASE_URL = "https://www.att.com"
DEFAULT_TIMEOUT = 20.0
DEFAULT_MIN_SUBMIT_INTERVAL = 300.0  # 5 minutes between submissions, minimum
DEFAULT_USER_AGENT = (
    "att-unlock-client/1.0 "
    "(single-account automation; contact: authorized test account operator)"
)

ENV_BASE_URL = "ATT_UNLOCK_BASE_URL"
ENV_USERNAME = "ATT_UNLOCK_USERNAME"
ENV_PASSWORD = "ATT_UNLOCK_PASSWORD"
ENV_SESSION_COOKIE = "ATT_UNLOCK_SESSION_COOKIE"
ENV_SESSION_COOKIE_FILE = "ATT_UNLOCK_SESSION_COOKIE_FILE"
ENV_SECRETS_FILE = "ATT_UNLOCK_SECRETS_FILE"
ENV_TIMEOUT = "ATT_UNLOCK_TIMEOUT"
ENV_MIN_SUBMIT_INTERVAL = "ATT_UNLOCK_MIN_SUBMIT_INTERVAL"
ENV_USER_AGENT = "ATT_UNLOCK_USER_AGENT"
ENV_VERIFY_TLS = "ATT_UNLOCK_VERIFY_TLS"

# Keys whose values must never appear in logs or serialized output.
SENSITIVE_KEYS = (
    "password",
    "passwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "credential",
)

_log = logging.getLogger("att_unlock")


def redact(value: Optional[str], keep: int = 0) -> str:
    """Return a safe rendering of a potentially sensitive value.

    By default the entire value is replaced. A prefix may be kept when useful
    for diagnostics (e.g. the cookie *name* list), but secret values are fully
    masked.
    """
    if value is None:
        return "<none>"
    if not value:
        return "<empty>"
    if keep > 0 and len(value) > keep:
        return f"{value[:keep]}<redacted:{len(value) - keep} chars>"
    return "<redacted>"


def is_sensitive_key(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in SENSITIVE_KEYS)


def redact_dict(d: Dict) -> Dict:
    """Deep-copy a dict with sensitive values masked (for logging/JSON out)."""
    out: Dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = redact_dict(v)
        elif isinstance(v, (list, tuple)):
            out[k] = [redact_dict(i) if isinstance(i, dict) else i for i in v]
        elif is_sensitive_key(k):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def load_secrets_file(path: str) -> Dict[str, str]:
    """Parse a local KEY=VALUE secrets file into the environment (no export
    to child processes, no persistence)."""
    values: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


@dataclass
class Endpoints:
    """Portal endpoints.

    ``confirmed`` marks paths verified against the public site on the date in
    docs/workflow-map.md. Paths marked ``confirmed=False`` are best-effort
    guesses at the JSON API behind the single-page app and MUST be calibrated
    in an authorized browser session (see README, "Calibrating endpoints").
    Every value can be overridden by the operator; never treat an unconfirmed
    endpoint as authoritative.
    """

    portal: str = "/deviceunlock/"
    step1: str = "/deviceunlock/unlockstep1"
    status_page: str = "/deviceunlock/status"
    eligibility: str = "/deviceunlock/api/eligibility"  # INFERRED - calibrate
    submit: str = "/deviceunlock/api/request"  # INFERRED - calibrate
    status: str = "/deviceunlock/api/status"  # INFERRED - calibrate
    login: str = "https://www.att.com/acctmgmt/login"  # INFERRED - calibrate
    confirmed: bool = field(default=False, repr=False)

    def resolve(self, base_url: str) -> "Endpoints":
        return Endpoints(
            portal=_join(base_url, self.portal),
            step1=_join(base_url, self.step1),
            status_page=_join(base_url, self.status_page),
            eligibility=_join(base_url, self.eligibility),
            submit=_join(base_url, self.submit),
            status=_join(base_url, self.status),
            login=self.login,
            confirmed=self.confirmed,
        )


def _join(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + ("" if path.startswith("/") else "/") + path


@dataclass
class Config:
    base_url: str = DEFAULT_BASE_URL
    endpoints: Endpoints = field(default_factory=Endpoints)
    timeout: float = DEFAULT_TIMEOUT
    min_submit_interval: float = DEFAULT_MIN_SUBMIT_INTERVAL
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True

    # Populated from the environment by load_config(); never serialized.
    username: Optional[str] = None
    password: Optional[str] = None
    session_cookie: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://", "https://")):
            raise ConfigError(f"base_url must be absolute: {self.base_url!r}")
        if self.timeout <= 0:
            raise ConfigError("timeout must be > 0")
        if self.min_submit_interval < 0:
            raise ConfigError("min_submit_interval must be >= 0")


def load_config(overrides: Optional[Dict[str, object]] = None) -> Config:
    """Build a Config from environment variables (and a local secrets file if
    named by ATT_UNLOCK_SECRETS_FILE), plus explicit overrides.

    Secrets stay in the returned Config object in memory only.
    """
    env = dict(os.environ)

    secrets_file = env.get(ENV_SECRETS_FILE)
    if secrets_file:
        if not os.path.isfile(secrets_file):
            raise ConfigError(f"secrets file not found: {secrets_file!r}")
        env.update(load_secrets_file(secrets_file))

    cfg = Config(
        base_url=env.get(ENV_BASE_URL, DEFAULT_BASE_URL),
        timeout=float(env.get(ENV_TIMEOUT, DEFAULT_TIMEOUT)),
        min_submit_interval=float(
            env.get(ENV_MIN_SUBMIT_INTERVAL, DEFAULT_MIN_SUBMIT_INTERVAL)
        ),
        user_agent=env.get(ENV_USER_AGENT, DEFAULT_USER_AGENT),
        verify_tls=str(env.get(ENV_VERIFY_TLS, "1")).lower()
        not in ("0", "false", "no", ""),
    )
    cfg.username = env.get(ENV_USERNAME)
    cfg.password = env.get(ENV_PASSWORD)

    cookie = env.get(ENV_SESSION_COOKIE)
    cookie_file = env.get(ENV_SESSION_COOKIE_FILE)
    if cookie_file:
        if not os.path.isfile(cookie_file):
            raise ConfigError(f"cookie file not found: {cookie_file!r}")
        with open(cookie_file, "r", encoding="utf-8") as fh:
            cookie = cookie or fh.read().strip()
    cfg.session_cookie = cookie

    for key, val in (overrides or {}).items():
        if val is None:
            continue
        if not hasattr(cfg, key):
            raise ConfigError(f"unknown config key: {key!r}")
        setattr(cfg, key, val)

    cfg.endpoints = Endpoints().resolve(cfg.base_url)
    _log.debug("config loaded: base_url=%s cookie=%s username=%s",
               cfg.base_url, redact(cfg.session_cookie),
               "<set>" if cfg.username else "<none>")
    return cfg
