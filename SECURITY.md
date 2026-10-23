# Security research notes — AT&T Device Unlock portal

**Method statement (important):** this project performed **passive
observation only** — public-page fetches, AT&T-published documentation, and
public third-party captures of portal output. **No authenticated calls, no
POSTs, no probing, no fuzzing, and no exploitation were performed, and no
proof-of-concept exploit code is included in this repository.** Active
security testing of AT&T production systems requires AT&T's explicit,
written authorization; if you have that (e.g., a signed agreement or a
covered bug-bounty scope), the hypotheses below are a starting checklist.
Any suspected vulnerability must be reported through AT&T's responsible
disclosure channels (their public bug-bounty program / security contact
page), not discussed publicly or used operationally.

## Observed (passive, 2026-09-09)

### S1. Status lookup is keyed by (IMEI + request number), not by session
**[CONFIRMED from the public status page.]** The public status form
(`att.com/deviceunlock/status`) states: "All you need is your device IMEI and
unlock request number." The request number is issued in the confirmation
email. This is the *documented* design: possession of the confirmation email
is the lookup credential.

Security implication (analysis, not an active test): an attacker who
compromises the confirmation email (or the mailbox) and knows the IMEI (easily
obtained from the device via `*#06#`, packaging, or retail records) can track
the request's state, including whether it was approved. The control that
mitigates this is the confidentiality of the email — hence the client's
diagnostics repeatedly warn to treat the confirmation email and request
number as sensitive, and the client never writes them to disk.

*Authorized-tester checklist item (only under an explicit agreement with
AT&T): does the underlying status API bind the (IMEI, request number) pair to
the caller's session, or does it answer any holder of the pair? Document the
behavior and report; do not enumerate other users' request numbers.*

### S2. The eligibility pre-check is part of the public (pre-login) flow
**[CONFIRMED flow shape.]** The public flow starts with "Do you have a mobile
number from AT&T? Yes/No" and the non-customer path proceeds from an IMEI
plus email — i.e., the portal is designed to accept an unauthenticated device
identifier before any account verification. If the underlying pre-check
discloses coarse eligibility state (eligible / not eligible) keyed only by
IMEI, that state is queryable by anyone who holds an IMEI. This is
by-design functionality of the consumer flow; it is noted here because
IMEIs are low-cost identifiers.

*Authorized-tester checklist item: characterize what state the pre-check
returns for (a) an eligible own device, (b) an ineligible own device, (c) an
unknown IMEI — then stop. Do not use the oracle to probe devices you do not
own.*

### S3. Edge protection / bot management
The portal sits behind edge protection. The research sandbox observed TLS
connection resets to non-browser TLS clients from a datacenter network, and
the public site is a hash-routed SPA behind standard edge tooling. The client
detects challenge-style responses (403/429/503 + known challenge wording)
and reports them as `temporary_error` + `DX_WAF_CHALLENGE` instead of
attempting any fingerprint, header, or token manipulation. **No bypass
technique is implemented or suggested.**

### S4. Confirmation link as a bearer token
**[DOCUMENTED flow.]** The email-confirmation link (valid 24 hours) acts as a
bearer token: whoever clicks it confirms the request. Consequence: the
confirmation email must be treated as credential-equivalent (do not forward
it, do not paste the link into shared channels). The client surfaces the link
only in the operator's own terminal output and warns it must be kept private.

### S5. CSRF handling
**[INFERRED mechanism, not yet verified live.]** The SPA is expected to carry
a CSRF token (anti-forgery cookie / meta tag / JSON-carried). The client
extracts all three patterns and sends the token on state-changing requests;
whether the live API *enforces* it is a calibration/authorized-test question,
not something this project tests.

### S6. Rate limiting
The client is built to **honor** throttling: 429/503 + `Retry-After` → capped
sleep, GETs only; plus a local minimum interval between submissions (default
5 minutes) and no automatic POST retries. No component of this repository
attempts to circumvent rate limits (no proxy rotation, no account
multiplexing, no request flooding).

## What this repository deliberately does not contain

- No PoC exploit, bypass, enumeration, or credential/session-extraction code.
- No payload mutations designed to change an eligibility or approval outcome.
- No MFA bypass, automation, or token-forgery logic.
- No test targets, endpoints, or parameters aimed at accounts other than the
  operator's own.

## Responsible disclosure

If, while using your **authorized** access, you observe behavior that looks
like a vulnerability (unauthorized data exposure, broken access control,
forgery opportunities):

1. **Stop** active investigation immediately.
2. Preserve minimal, sanitized evidence (status codes, field names — no
   other users' data, no full tokens).
3. Report through AT&T's responsible-disclosure channels (public bug-bounty
   program / security contact page on att.com) under your authorization
   scope.
4. Do not publish, do not test further, do not use the behavior operationally.
