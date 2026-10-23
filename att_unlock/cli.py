"""Command-line interface.

Commands
--------
  submit      run the full unlock workflow for ONE device (eligibility + request)
  status      look up an existing request by IMEI + request number
  diagnose    status lookup + diagnostic engine (or offline via --json-file)
  eligibility eligibility pre-check only (no request is submitted)
  calibrate   passive inspection of the public pages (session/CSRF/JS surface)

Exit codes
----------
  0   success (submitted / status retrieved / approved / diagnosis complete)
  2   client-side input error (e.g. malformed IMEI) or confirmation declined
  3   rejected / eligibility failed (final server decision)
  4   pending
  5   manual review / extra verification step required
  6   temporary error or blocked (no decision was made)
  7   authentication error
  8   configuration error
  130 interrupted by the user
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from dataclasses import asdict
from typing import Callable, List, Optional

from . import __version__
from .auth import AuthManager
from .client import HttpClient, UrllibTransport
from .config import Config, load_config, redact_dict
from .diagnostics import diagnose
from .models import (
    AttUnlockError,
    AuthError,
    BlockedError,
    ConfigError,
    Decision,
    Diagnostic,
    EligibilityResult,
    RawResponse,
    RateLimitedLocally,
    StatusResult,
    SubmitResult,
)
from .parser import classify_response
from .session import SessionState, extract_csrf
from .status import StatusService
from .unlock import UnlockService

EXIT_OK = 0
EXIT_INPUT = 2
EXIT_REJECTED = 3
EXIT_PENDING = 4
EXIT_MANUAL_REVIEW = 5
EXIT_TEMPORARY = 6
EXIT_AUTH = 7
EXIT_CONFIG = 8
EXIT_INTERRUPTED = 130

_DECISION_EXIT = {
    Decision.APPROVED: EXIT_OK,
    Decision.PENDING: EXIT_PENDING,
    Decision.MANUAL_REVIEW: EXIT_MANUAL_REVIEW,
    Decision.ELIGIBILITY_FAILED: EXIT_REJECTED,
    Decision.REJECTED: EXIT_REJECTED,
    Decision.INVALID_IMEI: EXIT_INPUT,
    Decision.TEMPORARY_ERROR: EXIT_TEMPORARY,
}


def _result_to_dict(result, findings: Optional[List[Diagnostic]] = None) -> dict:
    out = asdict(result)
    if findings:
        out["diagnostics"] = [f.to_dict() for f in findings]
    return redact_dict(out)


def _print_human(result, findings: Optional[List[Diagnostic]] = None) -> None:
    print(f"decision : {result.decision.value}")
    message = getattr(result, "message", "")
    if message:
        print(f"message  : {message}")
    if isinstance(result, SubmitResult):
        if result.request_id:
            print(f"request  : {result.request_id}")
        if result.email_confirmation_required:
            print("next     : click the confirmation link in the AT&T email within 24 hours")
        if result.confirmation_url:
            print(f"link     : {result.confirmation_url} (keep it private)")
    if isinstance(result, StatusResult):
        print(f"request  : {result.request_id or '-'}")
        if result.updated_at:
            print(f"updated  : {result.updated_at}")
    if findings:
        print("\ndiagnostics:")
        for f in findings:
            print(f"  [{f.severity.upper():7}] {f.code}: {f.title}")
            for line in f.actions:
                print(f"            - {line}")


class _Services:
    def __init__(self, config: Config, client: HttpClient):
        self.config = config
        self.client = client
        self.session = SessionState(cookie_header=config.session_cookie or "")
        self.auth = AuthManager(config, client)
        self.unlock = UnlockService(config, client, self.session, self.auth)
        self.status = StatusService(config, client, self.session)


def _default_services(args) -> _Services:
    config = _config_from_args(args)
    client = HttpClient(config)
    return _Services(config, client)


def _config_from_args(args) -> Config:
    overrides = {}
    if getattr(args, "base_url", None):
        overrides["base_url"] = args.base_url
    if getattr(args, "timeout", None):
        overrides["timeout"] = args.timeout
    if getattr(args, "min_interval", None) is not None:
        overrides["min_submit_interval"] = args.min_interval
    return load_config(overrides)


# --------------------------------------------------------------------- calibrate


def _cmd_calibrate(args, services: _Services) -> int:
    """Passive, read-only inspection of the public pages.

    Shows what a browser would observe: HTTP status, Set-Cookie *names*
    (values masked), CSRF token candidates (masked), script sources, and any
    embedded ``window.__*`` configuration globals. It never posts anything.
    """
    print("== passive calibration (GET-only, no requests submitted) ==")
    overall = EXIT_OK
    for label, path in (
        ("portal", services.config.endpoints.portal),
        ("step1", services.config.endpoints.step1),
        ("status", services.config.endpoints.status_page),
    ):
        try:
            resp = services.client.get(path)
        except AttUnlockError as err:
            print(f"[{label}] {path} -> ERROR: {err}")
            overall = EXIT_TEMPORARY
            continue
        print(f"\n[{label}] {resp.url}  ->  HTTP {resp.status} ({resp.elapsed_ms}ms)")
        names = sorted({c.split('=', 1)[0] for c in resp.set_cookies if '=' in c})
        print(f"  set-cookie names : {', '.join(names) if names else '-'}")
        for c in resp.set_cookies:
            name = c.split('=', 1)[0]
            print(f"    {name}=<redacted>")
        csrf = extract_csrf(resp.body, "; ".join(resp.set_cookies))
        if csrf:
            print(f"  csrf candidate   : <redacted, {len(csrf)} chars>")
        import re as _re2
        scripts = _re2.findall(r'<script[^>]+src=["\']([^"\']+)', resp.body)[:12]
        for s in scripts:
            print(f"  script           : {s[:140]}")
        import re as _re
        for m in _re.finditer(r"window\.__([A-Za-z0-9_]+)__", resp.body):
            print(f"  embedded config  : window.__{m.group(1)}__ (masked)")
    if overall == EXIT_OK:
        print("\nnote: the JSON API endpoints behind this SPA are NOT visible in "
              "the static HTML. In an authorized browser session, open devtools "
              "> Network, perform one legitimate step, and record the XHR "
              "paths as ATT_UNLOCK_* overrides (README: Calibrating endpoints).")
    return overall


# --------------------------------------------------------------------- commands


def _cmd_submit(args, services: _Services) -> int:
    if not args.yes:
        try:
            answer = input(
                f"This will submit a real unlock request for IMEI {args.imei} "
                "to the AT&T portal on the configured account.\n"
                "Type 'unlock' to continue: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return EXIT_INTERRUPTED
        if answer != "unlock":
            print("aborted (nothing submitted)")
            return EXIT_INPUT

    try:
        is_customer = None if args.customer is None else (args.customer == "yes")
        result = services.unlock.submit(
            args.imei,
            phone=args.phone,
            email=args.email,
            is_customer=is_customer,
            agree_to_requirements=True,
        )
    except AuthError as err:
        print(f"authentication error: {err}", file=sys.stderr)
        return EXIT_AUTH
    except RateLimitedLocally as err:
        print(f"local pace gate: {err}", file=sys.stderr)
        return EXIT_TEMPORARY
    except BlockedError as err:
        print(f"blocked: {err}", file=sys.stderr)
        return EXIT_TEMPORARY
    except ConfigError as err:
        print(f"configuration error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    findings = diagnose(result)
    if args.json:
        print(json.dumps(_result_to_dict(result, findings), indent=2, default=str))
    else:
        _print_human(result, findings)
    return _DECISION_EXIT[result.decision]


def _cmd_status(args, services: _Services) -> int:
    try:
        if args.wait:
            results = services.status.wait_for_decision(
                args.imei, args.request_id,
                max_checks=args.wait, interval=args.interval,
            )
            for r in results[:-1]:
                print(f"(check) {r.decision.value}: {r.message}"[:200])
            result: StatusResult = results[-1]
        else:
            result = services.status.get_status(args.imei, args.request_id)
    except AuthError as err:
        print(f"authentication error: {err}", file=sys.stderr)
        return EXIT_AUTH
    except BlockedError as err:
        print(f"blocked: {err}", file=sys.stderr)
        return EXIT_TEMPORARY
    except ConfigError as err:
        print(f"configuration error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    findings = diagnose(result)
    if args.json:
        print(json.dumps(_result_to_dict(result, findings), indent=2, default=str))
    else:
        _print_human(result, findings)
    return _DECISION_EXIT[result.decision]


def _cmd_eligibility(args, services: _Services) -> int:
    try:
        result: EligibilityResult = services.unlock.check_eligibility(
            args.imei, phone=args.phone
        )
    except AuthError as err:
        print(f"authentication error: {err}", file=sys.stderr)
        return EXIT_AUTH
    except BlockedError as err:
        print(f"blocked: {err}", file=sys.stderr)
        return EXIT_TEMPORARY
    except ConfigError as err:
        print(f"configuration error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    findings = diagnose(result)
    if args.json:
        print(json.dumps(_result_to_dict(result, findings), indent=2, default=str))
    else:
        _print_human(result, findings)
    return _DECISION_EXIT[result.decision]


def _load_offline_result(args) -> Optional[StatusResult]:
    """Build a StatusResult from a saved response file (offline diagnose)."""
    with open(args.json_file, "r", encoding="utf-8") as fh:
        raw_text = fh.read()
    try:
        data = json.loads(raw_text)
    except ValueError:
        data = None
    if isinstance(data, dict) and "status" in data and "body" in data:
        resp = RawResponse(
            status=int(data["status"]), headers={}, body=str(data["body"]),
            url="file://offline", elapsed_ms=0,
        )
    elif isinstance(data, dict):
        resp = RawResponse(
            status=200, headers={}, body=raw_text, url="file://offline", elapsed_ms=0,
        )
    else:
        resp = RawResponse(
            status=200, headers={}, body=raw_text, url="file://offline", elapsed_ms=0,
        )
    cls = classify_response(resp)
    return StatusResult(
        decision=cls.decision,
        imei=getattr(args, "imei", "") or "",
        request_id=cls.request_id or getattr(args, "request_id", None),
        message=cls.message,
        confidence=cls.confidence,
        matched=cls.matched,
        raw={"body": resp.body[:4000]},
    )


def _cmd_diagnose(args, services: _Services) -> int:
    if args.json_file:
        result = _load_offline_result(args)
        if result is None:
            print("could not read --json-file", file=sys.stderr)
            return EXIT_INPUT
        findings = diagnose(result, raw_text=result.raw.get("body", ""))
    else:
        if not args.imei or not args.request_id:
            print("diagnose requires --imei and --request-id (or --json-file)",
                  file=sys.stderr)
            return EXIT_INPUT
        try:
            result = services.status.get_status(args.imei, args.request_id)
        except AuthError as err:
            print(f"authentication error: {err}", file=sys.stderr)
            return EXIT_AUTH
        except BlockedError as err:
            print(f"blocked: {err}", file=sys.stderr)
            return EXIT_TEMPORARY
        except ConfigError as err:
            print(f"configuration error: {err}", file=sys.stderr)
            return EXIT_CONFIG
        findings = diagnose(result)

    if args.json:
        print(json.dumps(_result_to_dict(result, findings), indent=2, default=str))
    else:
        _print_human(result, findings)
    return _DECISION_EXIT[result.decision]


# ----------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="att_unlock",
        description="Single-account client for the AT&T Device Unlock portal "
                    "(operator's own authorized account only).",
    )
    p.add_argument("--version", action="version", version=f"att_unlock {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--base-url", help="override portal base URL (default: public portal)")
    p.add_argument("--timeout", type=float, help="per-request timeout in seconds")
    p.add_argument("--min-interval", type=float,
                   help="minimum seconds between submissions (default 300)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("submit", help="submit an unlock request for one device")
    sp.add_argument("--imei", required=True)
    sp.add_argument("--phone", help="10-digit AT&T mobile number (customer flow)")
    sp.add_argument("--email", help="email address for confirmation/approval mail")
    sp.add_argument("--customer", choices=["yes", "no"],
                    help="are you an AT&T customer?")
    sp.add_argument("--yes", action="store_true",
                    help="skip the interactive confirmation (still rate-gated)")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.set_defaults(func=_cmd_submit)

    sp = sub.add_parser("status", help="look up an existing request")
    sp.add_argument("--request-id", required=True)
    sp.add_argument("--imei", required=True)
    sp.add_argument("--wait", type=int, default=0,
                    help="optional: check up to N times (human-paced)")
    sp.add_argument("--interval", type=float, default=600.0,
                    help="seconds between --wait checks (default 600)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_status)

    sp = sub.add_parser("diagnose", help="status lookup + diagnostics (or offline)")
    sp.add_argument("--request-id")
    sp.add_argument("--imei")
    sp.add_argument("--json-file", help="saved response JSON; skips the network")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_diagnose)

    sp = sub.add_parser("eligibility", help="eligibility pre-check only")
    sp.add_argument("--imei", required=True)
    sp.add_argument("--phone")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=_cmd_eligibility)

    sp = sub.add_parser("calibrate", help="passive inspection of public pages")
    sp.set_defaults(func=_cmd_calibrate)
    return p


def _services_factory(args, factory: Optional[Callable]) -> _Services:
    if factory is not None:
        return factory(args)
    return _default_services(args)


def main(argv: Optional[List[str]] = None,
         services_factory: Optional[Callable[[], _Services]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        services = _services_factory(args, services_factory)
        return args.func(args, services)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except ConfigError as err:
        print(f"configuration error: {err}", file=sys.stderr)
        return EXIT_CONFIG
    except AttUnlockError as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_TEMPORARY
    except Exception as err:  # noqa: BLE001 - last-resort guard for the CLI
        logging.getLogger("att_unlock").exception("unexpected failure")
        print(f"unexpected error: {err}", file=sys.stderr)
        return EXIT_TEMPORARY


if __name__ == "__main__":
    raise SystemExit(main())
