#!/usr/bin/env python3
"""wifiaudit_client.py — submit a WPA capture to wifiaudit.io and pull the PDF.

Run this from a machine that can actually reach the API. The key is read from
the environment and never written to disk or to the repo:

    export WIFIAUDIT_API_KEY='wai_...'          # do not paste keys into chat
    python3 wifiaudit_client.py handshake.pcap --ssid "MyNetwork"

    # preview the exact HTTP request without spending an audit credit
    python3 wifiaudit_client.py handshake.pcap --ssid "MyNetwork" --dry-run

    # if the key is in a file you keep outside the repo
    python3 wifiaudit_client.py cap.pcap --ssid X --api-key-file ~/.wifiaudit.key

Notes on the published docs (they contradict each other):
  * marketing page  -> POST /v1/jobs      field: pcap, ssid, client_name
  * blog post       -> POST /api/v1/jobs  field: file, ssid, organization
  This client defaults to /api/v1/jobs + pcap= and automatically retries the
  other combination on 404/400/422, so either reading works.

Local pre-flight (free, no upload): if cap_analyze.py sits next to this script,
the capture is parsed first and the run is aborted when no M1/M2 pair exists —
an upload with no handshake just burns one of the 3 free audits and returns
"not found".

Exit codes: 0 done, 2 no handshake in file, 3 job failed, 4 usage/config error.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

DEFAULT_BASE = "https://api.wifiaudit.io"
PATH_VARIANTS = ["/api/v1/jobs", "/v1/jobs"]
FIELD_VARIANTS = ["pcap", "file"]


# ---------------------------------------------------------------------------
# multipart/form-data
# ---------------------------------------------------------------------------

def build_multipart(fields: dict, file_field: str, file_path: str):
    boundary = "----wifiaudit" + uuid.uuid4().hex
    out = bytearray()
    for k, v in fields.items():
        out += ("--%s\r\n" % boundary).encode()
        out += ('Content-Disposition: form-data; name="%s"\r\n\r\n' % k).encode()
        out += ("%s\r\n" % v).encode()
    name = os.path.basename(file_path)
    ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
    out += ("--%s\r\n" % boundary).encode()
    out += ('Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
            % (file_field, name)).encode()
    out += ("Content-Type: %s\r\n\r\n" % ctype).encode()
    with open(file_path, "rb") as f:
        out += f.read()
    out += ("\r\n--%s--\r\n" % boundary).encode()
    return bytes(out), "multipart/form-data; boundary=%s" % boundary


def request(url: str, key: str, method="GET", body=None, ctype=None, timeout=180):
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("X-API-Key", key)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "wifiaudit-client/1.0")
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers or {})


def as_json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"_raw": raw[:400].decode("utf-8", "replace")}


# ---------------------------------------------------------------------------
# pre-flight
# ---------------------------------------------------------------------------

def preflight(path: str):
    """Local-only sanity checks. Returns exit code or 0."""
    if not os.path.exists(path):
        print("error: no such file: %s" % path, file=sys.stderr)
        return 4
    size = os.path.getsize(path)
    head = open(path, "rb").read(4)
    if head[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
                        b"\x0a\x0d\x0d\x0a"):          # pcapng
        print("warning: %s does not start with a pcap/pcapng magic" % path, file=sys.stderr)
    print("capture : %s (%.2f MB, %s)" % (path, size / 1e6, head.hex()), file=sys.stderr)

    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cap_analyze
    except Exception:
        return 0                                   # no local dissector, skip
    try:
        recs, _ = cap_analyze.read_pcap(path)
        bssids = set()
        for _, b in recs:
            t, s, _ = cap_analyze.frame_class(b)
            if t == 0 and s in (8, 5) and len(b) >= 22:
                bssids.add(cap_analyze.MAC(b[16:22]))
        hss = cap_analyze.find_handshakes(recs, bssids)
    except Exception as e:
        print("warning: local parse skipped (%s)" % e, file=sys.stderr)
        return 0
    if not hss:
        print("\nNO M1/M2 PAIR in this capture -> the audit would return 'not found'.\n"
              "Re-capture: monitor mode on the AP's channel, wait for (or cause) one\n"
              "client association, keep the .cap. Do not spend an audit credit on it.",
              file=sys.stderr)
        return 2
    for h in hss:
        print("handshake: %s <-> %s  (ANonce from %s, 4-way complete=%s)"
              % (h["ap"], h["sta"], h["anonce_source"], h["complete_4way"]), file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--client-name", default=None, help="client_name / organization field")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--api-key-file", default=None)
    ap.add_argument("--out", default=None, help="PDF destination (default: <ssid>-wifiaudit.pdf)")
    ap.add_argument("--skip-preflight", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args()

    key = os.environ.get("WIFIAUDIT_API_KEY", "").strip()
    if not key and a.api_key_file:
        key = open(os.path.expanduser(a.api_key_file)).read().strip()
    if not key:
        print("error: set WIFIAUDIT_API_KEY (or --api-key-file).\n"
              "       Never hardcode the key in a script or commit it.", file=sys.stderr)
        return 4
    if not key.startswith("wai_"):
        print("warning: key does not start with 'wai_'", file=sys.stderr)

    rc = 0 if a.skip_preflight else preflight(a.capture)
    if rc:
        return rc

    if a.dry_run:
        body, ctype = build_multipart(
            {k: v for k, v in (("ssid", a.ssid), ("client_name", a.client_name)) if v},
            "pcap", a.capture)
        print("\nPOST %s/api/v1/jobs" % a.base)
        print("  X-API-Key: %s…%s (redacted)" % (key[:8], key[-4:]))
        print("  Content-Type: %s" % ctype)
        print("  body: %d bytes (ssid=%s, file=%s)" % (len(body), a.ssid, a.capture))
        print("\ncurl equivalent:\n"
              "  curl -X POST %s/api/v1/jobs \\\n"
              "    -H \"X-API-Key: $WIFIAUDIT_API_KEY\" \\\n"
              "    -F \"pcap=@%s\" \\\n"
              "    -F \"ssid=%s\"" % (a.base, a.capture, a.ssid))
        return 0

    fields = {"ssid": a.ssid}
    if a.client_name:
        fields["client_name"] = a.client_name

    # submit, tolerating the two documented request shapes
    job = None
    for path in PATH_VARIANTS:
        for fld in FIELD_VARIANTS:
            body, ctype = build_multipart(fields, fld, a.capture)
            url = a.base + path
            print("POST %s  (field=%s, %.2f MB)" % (url, fld, len(body) / 1e6), file=sys.stderr)
            st, raw, _ = request(url, key, "POST", body, ctype, a.timeout)
            js = as_json(raw)
            if st in (200, 201, 202) and (js.get("job_id") or js.get("id")):
                job = js.get("job_id") or js.get("id")
                print("accepted: job_id=%s status=%s" % (job, js.get("status")), file=sys.stderr)
                break
            print("  -> HTTP %d %s" % (st, json.dumps(js)[:200]), file=sys.stderr)
            if st in (401, 403):
                print("error: key rejected (%d). Rotate/check the key." % st, file=sys.stderr)
                return 4
            if st not in (400, 404, 405, 415, 422):
                return 3
        if job:
            break
    if not job:
        print("error: could not submit — all documented path/field combinations failed",
              file=sys.stderr)
        return 3

    # poll
    t0 = time.time()
    status = {}
    while time.time() - t0 < a.timeout:
        st, raw, _ = request("%s/api/v1/jobs/%s" % (a.base, job), key, timeout=60)
        status = as_json(raw)
        s = (status.get("status") or "").lower()
        print("  [%5.1fs] %s %s" % (time.time() - t0, s or st,
                                    {k: v for k, v in status.items()
                                     if k in ("result", "found_password", "password",
                                              "crack_duration_seconds")} or ""),
              file=sys.stderr)
        if s in ("done", "complete", "completed", "failed", "error"):
            break
        time.sleep(3)

    print("\njob result:\n" + json.dumps(status, indent=2))

    # report
    out = a.out or ("%s-wifiaudit.pdf" % "".join(
        c if c.isalnum() or c in "-_" else "_" for c in a.ssid))
    st, raw, hdrs = request("%s/api/v1/jobs/%s/report" % (a.base, job), key, timeout=120)
    if st == 200 and raw[:4] == b"%PDF":
        open(out, "wb").write(raw)
        print("\nPDF saved: %s (%d bytes)" % (out, len(raw)))
    else:
        print("\nreport download failed: HTTP %d %s" % (st, raw[:200]), file=sys.stderr)
        return 3

    if (status.get("result") or "").lower() in ("found", "vulnerable"):
        print("VERDICT: password recovered -> network is dictionary-vulnerable "
              "(found_password redacted in this output).")
    elif (status.get("result") or "").lower() in ("not_found", "not found", "passing"):
        print("VERDICT: not in the 14.4M dictionary -> not dictionary-vulnerable.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
