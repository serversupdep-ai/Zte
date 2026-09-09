# att_unlock — AT&T Device Unlock portal client

A Python client that reproduces the **legitimate, single-account** workflow of
AT&T's official Device Unlock portal (`https://www.att.com/deviceunlock/`):
eligibility pre-check, unlock-request submission, status lookup, and a
diagnostics engine that explains whatever decision the portal returns.

Built for the operator's **own authorized test account and own device(s)**.
Zero third-party runtime dependencies (Python 3.9+ stdlib only).

---

## Scope and authorization (read first)

This tool exists to automate what the operator can already do in a browser,
with the operator's own credentials, at a human pace. It is **not** a bulk
processing, automation-farming, or testing harness for AT&T's systems.

The client enforces, by construction:

| Constraint | How |
|---|---|
| Own account only | Credentials/session come from the operator's environment (`ATT_UNLOCK_*`). Cookie mode reuses a session the operator created in a real browser (MFA completed by a human). |
| One device, one request at a time | Single `--imei`; no batch inputs, no concurrency. |
| Human pace | Local minimum interval between submissions (default **300 s**, `ATT_UNLOCK_MIN_SUBMIT_INTERVAL`); POSTs are **never auto-retried**; server `Retry-After` is honored (capped at 15 min), never circumvented. |
| MFA is never bypassed | Login mode pauses and asks the human for the one-time code; cookie mode requires the human to have completed MFA in the browser. |
| Rejections are final | Ineligible/rejected/invalid outcomes stop the run. The client never mutates payloads to re-frame a rejection, never resubmits automatically, and contains no logic to "push" a rejection toward approval. |
| No secrets in output | All logging and `--json` output redact cookies, tokens, passwords, and any key containing sensitive substrings (covered by tests). |
| No active security testing | This repository performs **passive** observation only (see `SECURITY.md`). No PoC exploits, no probing, no enumeration. |

### On the "clean IMEI" assumption

The project brief asked to assume *"a clean IMEI guarantees unlock
eligibility."* That is **false**, and the tool is deliberately not built on
that premise. Per AT&T's published requirements (verified on the portal,
2026-09-09), an IMEI that is not reported lost/stolen is only **one** of
several necessary conditions:

1. Device purchased **60+ days** ago (12 months for prepaid) and not active on
   another AT&T account,
2. Device **paid in full** — installment balance zero,
3. Device **not reported lost/stolen** and not fraud-involved,
4. Account **current** (no past-due balance) for current customers,
5. Business devices: service commitment term ended; military deployment:
   separate documented path.

The *final* decision is a server-side business evaluation of AT&T's account
and device records. It is not exposed to the client, and this project does
not reverse-engineer, probe, or attempt to model that decision boundary. The
client can only **report** the outcome the portal returns and map it to the
published criteria (that is what the diagnostics engine does).

## Repository layout

```
att_unlock/
  client.py       HTTP layer: GET-only retries, no POST retry, Retry-After
                  honoring, local submission pace gate, redacted logging
  auth.py         cookie-mode / login-mode auth; human MFA prompt; no secret
                  leakage (tested)
  session.py      cookie header handling + CSRF token extraction
  unlock.py       eligibility pre-check + submission (eligibility gate makes
                  rejections final)
  status.py       status lookup (IMEI + request number) + opt-in human-paced
                  polling
  parser.py       IMEI validation (Luhn), request-id / confirmation-link
                  extraction, 7-state response classifier
  diagnostics.py  decision -> diagnostics engine (published requirements,
                  safe next steps, structural findings)
  cli.py          argparse CLI: submit / status / diagnose / eligibility /
                  calibrate
  config.py       env-var + local secrets-file config; redaction helpers
  models.py       dataclasses, Decision enum, error hierarchy
  tests/          120 offline unit tests (fake transport; no network)
docs/workflow-map.md   endpoint & workflow map (confirmed vs inferred)
SECURITY.md         passive security observations + disclosure guidance
.env.example      environment variable template
```

## Setup

Requires Python ≥ 3.9. No packages to install at runtime.

```bash
cd <repo>
python3 -m unittest discover -s att_unlock/tests -t . -v   # run the test suite
```

(Optional, to install as a console script / use pytest):

```bash
pip install -e .            # provides `att-unlock`
pip install -e '.[dev]'     # adds pytest for dev
```

### Credentials (your own account only)

Copy `.env.example` to a local secrets file and fill it in (or export the
variables directly). The client reads:

| Variable | Purpose |
|---|---|
| `ATT_UNLOCK_SESSION_COOKIE` | **Recommended.** Raw `Cookie:` header from your browser session after you logged in normally (MFA included). |
| `ATT_UNLOCK_SESSION_COOKIE_FILE` | Path to a file containing the cookie header. |
| `ATT_UNLOCK_USERNAME` / `ATT_UNLOCK_PASSWORD` | Login mode (interactive MFA prompt). Never logged. |
| `ATT_UNLOCK_SECRETS_FILE` | Path to a local `KEY=VALUE` file loaded into the environment. |
| `ATT_UNLOCK_BASE_URL` | Override the portal base URL (default: the public portal). |
| `ATT_UNLOCK_TIMEOUT` | Per-request timeout seconds (default 20). |
| `ATT_UNLOCK_MIN_SUBMIT_INTERVAL` | Local seconds between submissions (default 300). |

**Never** commit a filled secrets file; `.gitignore` excludes `.env`.

## Usage

```bash
# Passive inspection of the public pages (no requests submitted)
python3 -m att_unlock calibrate

# Eligibility pre-check only
python3 -m att_unlock eligibility --imei 35XXXXXXXXXXXXX

# Full workflow: pre-check, then submit if the portal says eligible
python3 -m att_unlock submit --imei 35XXXXXXXXXXXXX \
    --phone 5551234567 --email you@example.com --customer yes

# Look up an existing request (request number comes from the confirmation
# email, public examples show the NUL########## shape)
python3 -m att_unlock status --request-id NULXXXXXXXXXXX --imei 35XXXXXXXXXXXXX

# Status + diagnostic engine (or fully offline against a saved response)
python3 -m att_unlock diagnose --request-id NULXXXXXXXXXXX --imei 35XXXXXXXXXXXXX
python3 -m att_unlock diagnose --json-file saved-response.json

# Machine-readable output
python3 -m att_unlock status --request-id NULXXXXXXXXXXX --imei 35XXXXXXXXXXXXX --json
```

`submit` asks for an interactive confirmation (`Type 'unlock'`) unless
`--yes` is given, so a live request is never fired accidentally while
calibrating endpoints.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success / approved / diagnosis complete |
| 2 | client-side input error (e.g. malformed IMEI) or confirmation declined |
| 3 | rejected / eligibility failed (final server decision) |
| 4 | pending |
| 5 | manual review / extra verification step required |
| 6 | temporary error or blocked (no decision was made) |
| 7 | authentication error |
| 8 | configuration error |
| 130 | interrupted by the user |

## Calibrating the JSON endpoints

The portal is a hash-routed SPA. The **page URLs** and **form fields** used by
this client are confirmed against the public site (see
`docs/workflow-map.md`); the **JSON API paths behind the forms are inferred
and overridable** — the client marks them as such in `Endpoints.confirmed`
and the diagnostics engine flags "endpoint drift" when an HTML page comes
back where JSON was expected.

In an **authorized** browser session on your own account:

1. Open the portal, open DevTools → Network → XHR/Fetch.
2. Perform one legitimate step (e.g. the step-1 → step-2 transition, a status
   check).
3. Record the request method, path, payload keys, and response shape.
4. Point the client at the real paths by extending `Endpoints` (or by
   subclassing / patching `Config.endpoints` in your own harness) and verify
   the classifier against the real response — add the observed response
   shape as a test fixture.

Until calibrated, `submit`/`status` may return `temporary_error` with
`DX_ENDPOINT_DRIFT` diagnostics; `eligibility`, `status` in a browser, and
the manual flow always remain available as fallbacks.

## Authorized testing instructions

1. Use **only** the test account the operator is authorized to use.
2. Complete login/MFA in a real browser first; export the `Cookie` header
   (DevTools → Network → any request → Request Headers → `cookie`) into
   `ATT_UNLOCK_SESSION_COOKIE`.
3. Run `calibrate` and `eligibility` first (read-only steps).
4. Only then run `submit` for a device you own and that meets the published
   requirements; keep the confirmation email and request number.
5. Track the request via `status` / `diagnose`; the published response time
   is up to two business days.
6. If the portal ever reports a weakness you believe to be a vulnerability,
   stop testing and report it through AT&T's responsible-disclosure channel
   (see `SECURITY.md`). Do not expand testing.

## What this project will not do

- extract credentials or session material from any AT&T user other than the
  operator's own account;
- steal, replay across accounts, or farm session cookies/tokens;
- bypass, automate around, or skip MFA;
- forge authorization headers, tokens, or identity;
- alter, re-frame, or retry-into-approval any eligibility result;
- circumvent rate limits (the client honors them and adds its own pace gate);
- probe, fuzz, or exploit the production portal (no PoC exploit code exists
  in this repository by design).
