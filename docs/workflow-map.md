# AT&T Device Unlock — endpoint & workflow map

Passive research notes, **2026-09-09**. Sources: the public portal itself
(passive GET of public pages), AT&T-published support pages, and public
third-party screenshots of portal output. **No authenticated calls were made
in this research; no active probing of any kind was performed.**

Labels used below:

- **[CONFIRMED]** — observed directly on the public site on the research date.
- **[DOCUMENTED]** — stated in AT&T's own published support content.
- **[INFERRED]** — best-effort guess at behavior behind the SPA. The client
  treats these as calibratable values, never as fact.

---

## 1. Browser workflow

| Step | What the user does | Evidence |
|---|---|---|
| 0. Landing | `https://www.att.com/deviceunlock/` — brand picker + published unlock requirements (60+ days, paid in full, not lost/stolen, account current; prepaid 12 months; military deployment; business terms) | **[CONFIRMED]** rendered on the page |
| 1. Start request | `https://www.att.com/deviceunlock/unlockstep1` — "Do you have a mobile number from AT&T? Yes/No", 10-digit mobile number field (customer path), consent checkbox ("I've read the legal info. I agree to the device unlock eligibility requirements"), Back/Next | **[CONFIRMED]** rendered on the page |
| 2. Device identity | Non-customer path: enter IMEI (+ email confirmation per published flow). Customer path: phone number. Steps 2–3 are client-rendered (SPA), not in static HTML | **[CONFIRMED]** that the flow exists (links + help text); step 2/3 fields **[INFERRED]** |
| 3. Confirmation | Confirmation email with **unlock request number** (public examples: `NUL` + digits) and a **confirmation link valid for 24 hours**; AT&T customers also get a unique SMS link to check status without the request number | **[DOCUMENTED]** (support FAQ + public screenshots, e.g. a visible request number `NUL611583202886` in a third-party capture — masked here) |
| 4. Decision | AT&T responds **within two business days** (published); approval email contains the unlock code + device instructions (Android) or a remote unlock (iPhone — no code) | **[DOCUMENTED]** |
| 5. Status lookup | `https://www.att.com/deviceunlock/status` (served also as the `#/status` route) — form fields: **IMEI number** + **Request number** ("the unlock request number we emailed you") | **[CONFIRMED]** rendered on the page |

Routing note: the portal is a hash-routed SPA — `deviceunlock/#/status` and
`deviceunlock/status` serve the same app shell; step content beyond step 1 is
rendered client-side, which is why the static HTML contains only landing +
step 1.

## 2. Endpoint map

| # | Method & path | Purpose | Status |
|---|---|---|---|
| E1 | `GET https://www.att.com/deviceunlock/` | SPA shell + landing content | **[CONFIRMED]** |
| E2 | `GET https://www.att.com/deviceunlock/unlockstep1` | step-1 form (customer?/phone/consent) | **[CONFIRMED]** |
| E3 | `GET https://www.att.com/deviceunlock/status` | status form (IMEI + request number) | **[CONFIRMED]** |
| E4 | `GET https://www.att.com/wireless/imei-finder/` | official IMEI finder | **[CONFIRMED]** (linked from portal) |
| E5 | `POST {base}/deviceunlock/api/eligibility` | eligibility pre-check (IMEI) | **[INFERRED]** — calibrate |
| E6 | `POST {base}/deviceunlock/api/request` | submit unlock request (IMEI, phone/email, consent) | **[INFERRED]** — calibrate |
| E7 | `GET {base}/deviceunlock/api/status?imei=…&requestNumber=…` | status lookup | **[INFERRED]** — calibrate |
| E8 | `GET/POST https://www.att.com/acctmgmt/login` | MyAT&T login | **[INFERRED]** — calibrate; **cookie mode avoids this entirely (preferred)** |

Parameter names for E5–E7 (`imei`, `requestNumber`, `phoneNumber`, `email`,
`agree`, `attCustomer`) mirror the public form fields and are the client's
best-effort payload; they are **not** confirmed against the live API and must
be verified during calibration in an authorized session.

## 3. Request/response structures (sanitized, SYNTHETIC)

> All examples below are **synthesized for documentation** — they illustrate
> the shapes the client's parser/classifier handles. They are not captured
> from any live AT&T response in this project (no authenticated calls were
> made). Real shapes must be captured during calibration and added as test
> fixtures.

### 3.1 Eligibility pre-check (E5) — request

```http
POST /deviceunlock/api/eligibility HTTP/1.1
Host: www.att.com
Cookie: <operator session cookies — REDACTED>
X-CSRF-Token: <token — REDACTED>
Content-Type: application/json

{ "imei": "35XXXXXXXXXXXXX" }
```

### 3.2 Eligibility — eligible (synthetic)

```json
HTTP/1.1 200 OK
{ "status": "approved", "message": "Device is eligible for unlock" }
```

### 3.3 Eligibility — not eligible (synthetic)

```json
HTTP/1.1 200 OK
{
  "status": "ineligible",
  "message": "Your device does not meet the eligibility requirements. The device must be paid in full and active for more than 60 days."
}
```

### 3.4 Submit (E6) — request

```http
POST /deviceunlock/api/request HTTP/1.1
Cookie: <REDACTED>
X-CSRF-Token: <REDACTED>
Content-Type: application/json

{
  "imei": "35XXXXXXXXXXXXX",
  "phoneNumber": "5551234567",
  "email": "you@example.com",
  "attCustomer": true,
  "agree": true
}
```

### 3.5 Submit — accepted, request number issued (synthetic)

```json
HTTP/1.1 200 OK
{
  "status": "pending",
  "message": "Your unlock request has been submitted. A confirmation email is on its way.",
  "requestNumber": "NULXXXXXXXXXXX"
}
```

### 3.6 Submit — email confirmation step required (synthetic)

```json
HTTP/1.1 200 OK
{
  "status": "pending",
  "message": "Email confirmation required. Select the link in the email within 24 hours to confirm your unlock request.",
  "requestNumber": "NULXXXXXXXXXXX",
  "confirmUrl": "https://www.att.com/deviceunlock/confirm?token=***"
}
```

### 3.7 Status lookup (E7) — pending / approved / rejected (synthetic)

```json
{ "status": "pending",  "message": "Your request is being processed. We will respond within two business days.", "requestNumber": "NULXXXXXXXXXXX", "updatedAt": "2026-09-09T10:00:00Z" }
```
```json
{ "status": "approved", "message": "Your request has been approved. An email with unlock instructions has been sent.", "requestNumber": "NULXXXXXXXXXXX" }
```
```json
{ "status": "rejected", "message": "Your request was rejected. The device does not meet the eligibility requirements.", "requestNumber": "NULXXXXXXXXXXX" }
```

### 3.8 Invalid IMEI (synthetic)

```json
{ "status": "invalidimei", "message": "Invalid IMEI number provided. Please verify and try again." }
```

## 4. Field → normalized decision map (what `parser.py` implements)

| Portal field value / wording (observed vocabulary) | Normalized `Decision` |
|---|---|
| `status: approved` / "has been approved" / "unlock code sent" | `approved` |
| `status: pending, in_process, processing, submitted, received, queued` / "within two business days" | `pending` |
| `status: rejected, denied, notapproved` / "was rejected" / "denied" | `rejected` |
| `status: invalidimei, imeinotfound, notfound` / "invalid IMEI" | `invalid_imei` |
| `status: ineligible, noteligible, eligibilityfailed` / "does not meet the eligibility requirements" / "unable to unlock" | `eligibility_failed` |
| HTTP 5xx, timeouts, 429/503, challenge/blocked pages, HTML-instead-of-JSON (endpoint drift) | `temporary_error` |
| `status: under_review, manual_review, action_required` / "email confirmation" / "click the link in the email" | `manual_review` |

Precedence: transport/HTTP-level failure → explicit status field → text
keywords (invalid-imei > eligibility > rejected > manual-review > pending >
approved) → structural fallback (HTML where JSON expected ⇒ temporary error,
never guessed as approved). Ambiguity resolves to the *conservative* state:
the client never declares `approved` on a weak signal, and a `pending`
pre-check withholds the real submission.

## 5. Session, CSRF, versioning (passive observations)

- **[CONFIRMED]** The portal is session-cookie based (standard web app) and a
  hash-routed SPA; the static shell exposes no API config in the landing HTML
  (verified by passive fetch: only landing + step-1 content + scripts).
- **[INFERRED]** CSRF protection for form POSTs (meta tag / anti-forgery
  cookie / JSON-carried token). The client extracts all three patterns and
  sends the token in `X-CSRF-Token`/`X-XSRF-TOKEN`; during calibration, note
  which mechanism the live flow uses.
- **[DOCUMENTED]** The confirmation step (24-hour email link) and the request
  number double as the status-lookup credential — i.e., "possession of the
  email" is the lookup authorization for the public status form.
- Versioning: no API version markers were observed in the public shell
  **[CONFIRMED-for-absence]**; treat response shapes as unstable and pin
  calibration fixtures.
- Edge/WAF: the portal sits behind edge protection; challenge pages
  ("unusual traffic" style) are possible for non-browser clients. The client
  detects and reports these as `temporary_error` + `DX_WAF_CHALLENGE` rather
  than attempting any bypass.

## 6. Research method & limits

- Method: passive GET of public pages (research tool fetch of
  `att.com/deviceunlock/`, `/unlockstep1`, `/status`, `#/status`), AT&T
  support articles (KM1008728, FAQ, device-unlock PDF), and public
  third-party captures for the request-number shape. No authenticated
  session was used; no POST was made against the portal during research.
- The sandbox performing this research had **no direct egress** to
  `www.att.com` (TLS resets on direct connections; only the platform's
  passive fetch tooling succeeded), which independently limited the research
  to passive observation.
- Consequence: E5–E8 and all JSON parameter names are **[INFERRED]** and must
  be calibrated in an authorized browser session before live use.
