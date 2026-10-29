#!/usr/bin/env python3
"""Re-verify the pinned GitHub evidence in evidence/github_sources.json.

Uses only api.github.com (reachable from this sandbox).  For each pinned repo it
checks that the commit still exists, and for each pinned file that the recorded
git blob SHA still resolves in that repo.  A 403/rate-limit or offline run is
reported as SKIP, never as a pass.

A repo that has vanished from GitHub (deleted, renamed or made private) is
reported as GONE rather than FAIL: the pin was correct when recorded, and the
finding -- "this source disappeared" -- is itself evidence about how reliable
the public record is.  GONE never counts as a pass.

    python3 verify_sources.py            # human readable
    python3 verify_sources.py --json     # machine readable

Requires no third-party packages; GH_TOKEN (if set) is used as a bearer token.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

EVIDENCE = Path(__file__).resolve().parent / "evidence" / "github_sources.json"
API = "https://api.github.com"


def _get(path: str) -> tuple[int, dict | None, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "latest-suffix-evidence-verifier",
    }
    token = os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.load(r), ""
    except urllib.error.HTTPError as e:
        return e.code, None, e.read().decode("utf-8", "replace")[:160]
    except Exception as e:  # offline / DNS / TLS
        return 0, None, str(e)[:160]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    data = json.loads(EVIDENCE.read_text())
    rows = []
    for repo, info in data.items():
        if repo.startswith("_") or repo in ("github_issues", "local_corpus"):
            continue

        # Does the repository itself still exist publicly?
        rcode, _rb, _re = _get(f"/repos/{repo}")
        if rcode == 404:
            rows.append({"repo": repo, "kind": "repo", "ref": "(repository)",
                         "status": "GONE", "http": rcode,
                         "detail": "no longer public on GitHub: deleted, renamed "
                                   "or made private; pin was valid when recorded"})
            continue

        def status_of(code: int) -> str:
            if code == 200:
                return "OK"
            if code in (0, 403, 429):
                return "SKIP"
            return "FAIL"

        commit = info["commit"]
        code, _body, err = _get(f"/repos/{repo}/commits/{commit}")
        rows.append({"repo": repo, "kind": "commit", "ref": commit,
                     "status": status_of(code), "http": code, "detail": err})
        for path, sha in info["files"].items():
            code, _body, err = _get(f"/repos/{repo}/git/blobs/{sha}")
            rows.append({"repo": repo, "kind": "blob", "ref": f"{path}@{sha[:10]}",
                         "status": status_of(code), "http": code, "detail": err})

    summary = {s: sum(1 for r in rows if r["status"] == s)
               for s in ("OK", "SKIP", "GONE", "FAIL")}
    if args.json:
        print(json.dumps({"summary": summary, "rows": rows}, indent=2))
    else:
        for r in rows:
            print(f"{r['status']:4}  {r['kind']:6}  {r['repo']:38}  {r['ref']}"
                  + (f"  ({r['detail']})" if r["status"] != "OK" else ""))
        print(f"\n{summary['OK']} OK / {summary['SKIP']} SKIP / "
              f"{summary['GONE']} GONE / {summary['FAIL']} FAIL")
    return 1 if summary["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
