#!/usr/bin/env bash
# run_audit.sh — submit the inwi capture to the WiFiAudit API, poll, download the PDF.
#
# Everything is filled in below except the API key, which is read from the
# environment (never hard-coded, never echoed, never written to disk):
#
#     export WIFIAUDIT_API_KEY='wai_...'
#     ./run_audit.sh
#
# Usage:
#     ./run_audit.sh                 # submit + poll + download PDF
#     ./run_audit.sh --dry-run       # show the request, upload nothing
#     ./run_audit.sh --ssid 'X'      # override the SSID (only if you know better)
#
set -uo pipefail

# --------------------------------------------------------------------------
# All request details
# --------------------------------------------------------------------------
API_BASE="https://api.wifiaudit.io"
PATH_PRIMARY="/api/v1/jobs"          # endpoint you specified
PATH_FALLBACK="/v1/jobs"             # marketing-page variant
CAPTURE="HS_inwi_Home_4G_6A6EDE10_20_31.cap"
SSID_EXPECTED="inwi Home 4G 6A6EDE"  # verified from the beacon IE, spaces preserved
CLIENT_NAME="${CLIENT_NAME:-}"       # optional white-label field
OUT_PDF="${OUT_PDF:-audit-inwi.pdf}"
POLL_TIMEOUT=300

DRY_RUN=0
SSID="$SSID_EXPECTED"
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --ssid) SSID="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 64 ;;
  esac
  shift
done

say() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

# --------------------------------------------------------------------------
# 0. key
# --------------------------------------------------------------------------
if [ -z "${WIFIAUDIT_API_KEY:-}" ]; then
  if [ -t 0 ]; then
    printf 'X-API-Key (hidden): ' >&2
    read -rs WIFIAUDIT_API_KEY; printf '\n' >&2
  fi
fi
if [ -z "${WIFIAUDIT_API_KEY:-}" ]; then
  err "error: set WIFIAUDIT_API_KEY in the environment first."
  err "       export WIFIAUDIT_API_KEY='wai_...'"
  exit 64
fi
KEY_MASKED="$(printf '%s' "$WIFIAUDIT_API_KEY" | cut -c1-8)…$(printf '%s' "$WIFIAUDIT_API_KEY" | tail -c 5)"

# --------------------------------------------------------------------------
# 1. file checks
# --------------------------------------------------------------------------
[ -f "$CAPTURE" ] || { err "error: capture not found: $CAPTURE"; exit 66; }
[ -r "$CAPTURE" ] || { err "error: capture not readable: $CAPTURE"; exit 66; }

SIZE=$(wc -c < "$CAPTURE" | tr -d ' ')
MAGIC=$(head -c 4 "$CAPTURE" | od -An -tx1 | tr -d ' \n')
SHA=$(sha256sum "$CAPTURE" | cut -d' ' -f1)
say "file      : $CAPTURE"
say "size      : $SIZE bytes ($(awk -v s="$SIZE" 'BEGIN{printf "%.2f", s/1048576}') MB)"
say "magic     : $MAGIC  (d4c3b2a1 = libpcap LE)"
say "sha256    : $SHA"
case "$MAGIC" in
  d4c3b2a1|a1b2c3d4|4d3cb2a1|a1b23c4d|0a0d0d0a) : ;;
  *) err "error: not a pcap/pcapng file"; exit 65 ;;
esac
say "key       : $KEY_MASKED (redacted)"

# --------------------------------------------------------------------------
# 2. SSID verification against the capture itself
# --------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1 && [ -f cap_analyze.py ]; then
  FOUND_SSID=$(python3 - "$CAPTURE" <<'PY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("cap_analyze", "cap_analyze.py")
C = importlib.util.module_from_spec(spec); spec.loader.exec_module(C)
recs, _ = C.read_pcap(sys.argv[1])
seen = set()
for _, b in recs:
    t, s, _ = C.frame_class(b)
    if t == 0 and s in (8, 5) and len(b) >= 36:
        for eid, v in C.parse_ies(b[36:]):
            if eid == 0 and v:
                seen.add(v.decode("utf-8", "replace"))
print("|".join(sorted(seen)))
PY
)
  say "ssid found: $FOUND_SSID"
  if [ -n "$FOUND_SSID" ] && [ "$FOUND_SSID" != "$SSID" ]; then
    err ""
    err "SSID MISMATCH — '$SSID' is not the ESSID in this capture."
    err "  capture says : $FOUND_SSID"
    err "  you asked for: $SSID"
    err "  The API matches the SSID against the beacon; a wrong value is"
    err "  rejected or returns 'not found' with no way to tell them apart."
    err "  Re-run with:  --ssid '$FOUND_SSID'   (or no --ssid to use it automatically)"
    exit 65
  fi
  say "ssid      : '$SSID'  (matches capture)"
else
  say "ssid      : '$SSID'  (cap_analyze.py absent — not verified locally)"
fi

[ "$DRY_RUN" = "1" ] && {
  say ""
  say "DRY RUN — nothing uploaded. Request would be:"
  say "  POST $API_BASE$PATH_PRIMARY"
  say "  X-API-Key: $KEY_MASKED"
  say "  -F pcap=@$CAPTURE"
  say "  -F ssid=$SSID"
  exit 0
}

# --------------------------------------------------------------------------
# 3. submit
# --------------------------------------------------------------------------
submit() { # $1 = path, $2 = file field name -> "HTTPCODE|BODY"
  local path="$1" field="$2" args=(-sS -w '\n%{http_code}' -X POST "$API_BASE$path"
    -H "X-API-Key: $WIFIAUDIT_API_KEY" -H "Accept: application/json"
    -F "$field=@$CAPTURE" -F "ssid=$SSID")
  [ -n "$CLIENT_NAME" ] && args+=(-F "client_name=$CLIENT_NAME")
  local out; out=$(curl "${args[@]}" 2>&1)
  local code; code=$(printf '%s' "$out" | tail -n1)
  local body; body=$(printf '%s' "$out" | sed '$d')
  printf '%s|%s' "$code" "$(printf '%s' "$body" | tr -d '\n' | sed "s/$WIFIAUDIT_API_KEY/<KEY>/g")"
}

say ""
say "--- submitting ---"
JOB_ID=""; RESP=""
for path in "$PATH_PRIMARY" "$PATH_FALLBACK"; do
  for field in pcap file; do
    say "POST $API_BASE$path  (field=$field)"
    R=$(submit "$path" "$field")
    CODE="${R%%|*}"; BODY="${R#*|}"
    say "  HTTP $CODE"
    say "  $BODY"
    JOB_ID=$(printf '%s' "$BODY" | python3 -c 'import sys,json;
d=json.load(sys.stdin) if sys.stdin.isatty()==False else {}
' 2>/dev/null) || true
    JOB_ID=$(printf '%s' "$BODY" | python3 -c '
import sys, json
try: d = json.load(sys.stdin)
except Exception: print(""); raise SystemExit
print(d.get("job_id") or d.get("id") or "")' 2>/dev/null)
    RESP="$BODY"
    if [ -n "$JOB_ID" ] && [ "$CODE" != "000" ]; then break 2; fi
    case "$CODE" in
      000|400|404|405|415|422) continue ;;   # try the next documented shape
      *) break 2 ;;
    esac
  done
done

if [ -z "$JOB_ID" ]; then
  err ""
  err "FAILED: no job_id returned."
  case "${CODE:-000}" in
    000) err "  HTTP 000 = no HTTP response at all. Is the host reachable from here?"
         err "  (this sandbox blocks it; your machine probably will not)." ;;
    401|403) err "  Key rejected. Rotate it at https://api.wifiaudit.io and retry." ;;
    404) err "  Endpoint path wrong. We tried $PATH_PRIMARY and $PATH_FALLBACK." ;;
    422|400) err "  Payload rejected — check the ssid and that the file has a handshake." ;;
  esac
  exit 67
fi
say ""
say "job_id    : $JOB_ID"

# --------------------------------------------------------------------------
# 4. poll
# --------------------------------------------------------------------------
say "--- polling (timeout ${POLL_TIMEOUT}s) ---"
T0=$(date +%s); STATUS=""; LAST=""
while :; do
  R=$(curl -sS -w '\n%{http_code}' "$API_BASE$PATH_PRIMARY/$JOB_ID" \
        -H "X-API-Key: $WIFIAUDIT_API_KEY" 2>&1)
  CODE=$(printf '%s' "$R" | tail -n1); BODY=$(printf '%s' "$R" | sed '$d')
  STATUS=$(printf '%s' "$BODY" | python3 -c '
import sys, json
try: d = json.load(sys.stdin)
except Exception: print(""); raise SystemExit
print((d.get("status") or "").lower())' 2>/dev/null)
  ELAPSED=$(( $(date +%s) - T0 ))
  if [ "$BODY" != "$LAST" ]; then
    say "  [${ELAPSED}s] HTTP $CODE status='$STATUS'"
    say "  $BODY"
    LAST="$BODY"
  fi
  case "$STATUS" in
    done|complete|completed|failed|error) break ;;
  esac
  [ "$ELAPSED" -ge "$POLL_TIMEOUT" ] && { err "  timeout"; break; }
  sleep 3
done

# --------------------------------------------------------------------------
# 5. verdict + report
# --------------------------------------------------------------------------
say ""
say "--- verdict ---"
printf '%s' "$LAST" | python3 -c '
import sys, json
try: d = json.load(sys.stdin)
except Exception: print("  (unparseable response)"); raise SystemExit
res = (d.get("result") or d.get("status") or "").lower()
pw  = d.get("found_password") or d.get("password") or ""
print("  status          :", d.get("status"))
print("  result          :", d.get("result"))
print("  password found  :", ("YES (" + str(len(pw)) + " chars)") if pw else "no")
print("  duration        :", d.get("crack_duration_seconds"))
if res in ("found", "vulnerable"):
    print("  => VULNERABLE: passphrase is in the 14.4M dictionary.")
elif res in ("not_found", "not found", "passing"):
    print("  => PASSING: not present in the 14.4M dictionary.")
else:
    print("  => inconclusive; read the fields above.")
'

say "--- report ---"
CODE=$(curl -sS -o "$OUT_PDF" -w '%{http_code}' \
        "$API_BASE$PATH_PRIMARY/$JOB_ID/report" -H "X-API-Key: $WIFIAUDIT_API_KEY" 2>&1)
if [ "$CODE" = "200" ] && [ "$(head -c 4 "$OUT_PDF")" = "%PDF" ]; then
  say "  saved $OUT_PDF ($(wc -c < "$OUT_PDF" | tr -d ' ') bytes)"
else
  err "  report download failed: HTTP $CODE"
  rm -f "$OUT_PDF"
  exit 67
fi
say ""
say "done. job_id=$JOB_ID"
