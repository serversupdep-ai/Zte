#!/usr/bin/env python3
"""Check a newline-delimited domain list against authoritative RDAP registries.

Uses only Python's standard library. A .com 404 from Verisign RDAP means
available; a 200 means registered. Network errors and rate limits are reported
as unknown, never as available. Suitable for large lists when run on a machine
with outbound access to RDAP services.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

FIELDS = ("domain", "status", "http_status", "checked_at", "rdap_url", "detail")
RETRYABLE_HTTP = {429, 500, 502, 503, 504}


def canonical_domain(value: str, default_tld: str) -> str | None:
    """Normalize a bare label or domain, returning None for invalid input."""
    value = value.strip().lower().rstrip(".")
    if not value or "://" in value or any(c in value for c in "/?#@"):
        return None
    if "." not in value:
        value = f"{value}.{default_tld.lstrip('.').lower()}"
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253:
        return None
    labels = value.split(".")
    if len(labels) < 2:
        return None
    if any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        return None
    return value


def rdap_url(domain: str) -> str:
    # Verisign is the authoritative RDAP operator for .com. rdap.org provides
    # registry discovery/redirects for other TLDs.
    if domain.endswith(".com"):
        return f"https://rdap.verisign.com/com/v1/domain/{quote(domain, safe='.-')}"
    return f"https://rdap.org/domain/{quote(domain, safe='.-')}"


class RequestPacer:
    """Space request starts across worker threads to avoid hammering registries."""

    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, delay)
        self.lock = threading.Lock()
        self.next_at = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            wait_for = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.delay
        if wait_for:
            time.sleep(wait_for)


def retry_delay(error: HTTPError, attempt: int) -> float:
    value = error.headers.get("Retry-After") if error.headers else None
    if value:
        try:
            return min(120.0, max(0.0, float(value)))
        except ValueError:
            try:
                date = parsedate_to_datetime(value)
                return min(120.0, max(0.0, (date - datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(30.0, 1.5**attempt)


def check_domain(
    domain: str,
    pacer: RequestPacer,
    timeout: float,
    retries: int,
) -> dict[str, str]:
    url = rdap_url(domain)
    last_status = ""
    detail = ""
    for attempt in range(retries + 1):
        pacer.wait()
        request = Request(
            url,
            headers={
                "Accept": "application/rdap+json, application/json",
                "User-Agent": "NamevetBulkDomainChecker/1.0 (+https://github.com/MikaStiebitz/Availability-Checker)",
            },
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                code = response.getcode()
                # Read a small portion so the response is consumed and the
                # connection can be returned cleanly; 200 is the registration signal.
                response.read(4096)
                return result(domain, "taken" if code == 200 else "unknown", code, url, "")
        except HTTPError as exc:
            last_status = str(exc.code)
            if exc.code == 404:
                return result(domain, "available", exc.code, url, "")
            if exc.code in RETRYABLE_HTTP and attempt < retries:
                time.sleep(retry_delay(exc, attempt))
                continue
            detail = f"HTTP {exc.code}"
        except (URLError, TimeoutError, OSError) as exc:
            if attempt < retries:
                time.sleep(min(30.0, 1.5**attempt))
                continue
            detail = str(getattr(exc, "reason", exc))[:240]
        except Exception as exc:  # keep one bad response from stopping a 10k run
            detail = str(exc)[:240]
        return result(domain, "unknown", last_status, url, detail or "unclassified RDAP response")
    return result(domain, "unknown", last_status, url, detail or "retry limit reached")


def result(domain: str, status: str, http_status: int | str, url: str, detail: str) -> dict[str, str]:
    return {
        "domain": domain,
        "status": status,
        "http_status": str(http_status),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rdap_url": url,
        "detail": detail,
    }


def load_domains(path: Path, default_tld: str) -> tuple[list[str], list[tuple[str, str]]]:
    domains: list[str] = []
    invalid: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        # Accept simple CSV/TSV exports when the first column is the domain.
        raw = re.split(r"[,\t;]", raw, maxsplit=1)[0].strip().strip('"')
        if raw.lower() in {"domain", "domains", "name", "hostname"}:
            continue
        domain = canonical_domain(raw, default_tld)
        if domain is None:
            invalid.append((raw, f"invalid domain on input line {line_number}"))
        elif domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains, invalid


def read_existing(output: Path) -> dict[str, dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    if not output.exists():
        return found
    try:
        with output.open(newline="", encoding="utf-8") as stream:
            for row in csv.DictReader(stream):
                if row.get("domain"):
                    found[row["domain"]] = {field: row.get(field, "") or "" for field in FIELDS}
    except (OSError, csv.Error):
        print(f"Warning: could not read existing output {output}; starting fresh.", file=sys.stderr)
    return found


def write_progress(output: Path, row: dict[str, str]) -> None:
    new_file = not output.exists() or output.stat().st_size == 0
    with output.open("a", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(row)
        stream.flush()


def compact_output(output: Path, domains: list[str], records: dict[str, dict[str, str]], invalid: list[tuple[str, str]]) -> None:
    """Rewrite checkpoint rows in input order, retaining one row per input item."""
    temp = output.with_name(output.name + ".tmp")
    with temp.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        for domain in domains:
            writer.writerow(records[domain])
        for raw, detail in invalid:
            writer.writerow(result(raw, "invalid", "", "", detail))
    temp.replace(output)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bulk-check domain names using authoritative RDAP responses.")
    parser.add_argument("input", type=Path, help="newline-delimited domain names or bare names")
    parser.add_argument("-o", "--output", type=Path, default=Path("domains_checked.csv"), help="CSV output/checkpoint path")
    parser.add_argument("--default-tld", default="com", help="suffix for bare names (default: com)")
    parser.add_argument("--workers", type=int, default=4, help="parallel workers (default: 4)")
    parser.add_argument("--delay", type=float, default=0.25, help="minimum seconds between request starts (default: 0.25)")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds (default: 10)")
    parser.add_argument("--retries", type=int, default=3, help="retries for temporary failures (default: 3)")
    args = parser.parse_args()

    if args.workers < 1 or args.delay < 0 or args.timeout <= 0 or args.retries < 0:
        parser.error("workers must be >= 1, delay >= 0, timeout > 0, and retries >= 0")
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output paths must be different")

    try:
        domains, invalid = load_domains(args.input, args.default_tld)
    except OSError as exc:
        parser.error(f"cannot read input: {exc}")
    if not domains and not invalid:
        parser.error("input contains no domain names")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    records = read_existing(args.output)
    todo = [domain for domain in domains if records.get(domain, {}).get("status") not in {"available", "taken"}]
    print(f"Unique domains: {len(domains)}; already checked: {len(domains) - len(todo)}; invalid lines: {len(invalid)}", file=sys.stderr)
    print(f"Query rate limit: one request every {args.delay:g}s; output/checkpoint: {args.output}", file=sys.stderr)

    pacer = RequestPacer(args.delay)
    done = 0
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(check_domain, domain, pacer, args.timeout, args.retries): domain for domain in todo}
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    row = future.result()
                except Exception as exc:
                    row = result(domain, "unknown", "", rdap_url(domain), str(exc)[:240])
                records[domain] = row
                write_progress(args.output, row)
                done += 1
                if done % 100 == 0 or done == len(todo):
                    print(f"Checked {done}/{len(todo)}", file=sys.stderr)
    except KeyboardInterrupt:
        print("Interrupted. Completed rows are saved; rerun the same command to resume.", file=sys.stderr)
        return 130

    compact_output(args.output, domains, records, invalid)
    counts = {name: 0 for name in ("available", "taken", "unknown", "invalid")}
    for domain in domains:
        status = records.get(domain, {}).get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    counts["invalid"] = len(invalid)
    print(json.dumps({"unique_domains": len(domains), **counts, "output": str(args.output)}, indent=2))
    if counts["unknown"]:
        print("Some lookups were inconclusive. Rerun to retry unknown domains; unknown is not available.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
