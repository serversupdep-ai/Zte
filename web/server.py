#!/usr/bin/env python3
"""Dependency-free web UI for the att_unlock research project.

Serves a single-page demo that exercises the REAL parser + diagnostics
engine offline. No request ever leaves the sandbox to AT&T (or anywhere):
the "diagnostic console" only runs pure local classification logic over a
response the visitor pastes (or picks from a synthetic preset).

Run:  python3 web/server.py [--port 8000]
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Make the package importable regardless of CWD.
sys.path.insert(0, __file__.rsplit("/", 2)[0])

from att_unlock.diagnostics import diagnose  # noqa: E402
from att_unlock.models import (  # noqa: E402
    Decision,
    EligibilityResult,
    RawResponse,
    StatusResult,
    SubmitResult,
)
from att_unlock.parser import (  # noqa: E402
    classify_response,
    clean_imei,
    luhn_check,
    validate_imei,
)

TITLE = "att_unlock · AT&T Device Unlock research"

PRESETS = [
    {
        "id": "approved",
        "label": "Approved",
        "kind": "status",
        "status": 200,
        "body": "{\"status\": \"approved\", \"message\": \"Your request has been approved. An email with unlock instructions has been sent.\", \"requestNumber\": \"NUL123456789012\", \"updatedAt\": \"2026-09-09T10:00:00Z\"}",
    },
    {
        "id": "pending",
        "label": "Pending",
        "kind": "status",
        "status": 200,
        "body": "{\"status\": \"pending\", \"message\": \"Your request is being processed. We will respond within two business days.\", \"requestNumber\": \"NUL123456789012\"}",
    },
    {
        "id": "rejected",
        "label": "Rejected",
        "kind": "status",
        "status": 200,
        "body": "{\"status\": \"rejected\", \"message\": \"Your request was rejected. The device does not meet the eligibility requirements.\", \"requestNumber\": \"NUL123456789012\"}",
    },
    {
        "id": "eligibility",
        "label": "Eligibility failed",
        "kind": "eligibility",
        "status": 200,
        "body": "{\"status\": \"ineligible\", \"message\": \"Your device does not meet the eligibility requirements. The device must be paid in full and active for more than 60 days.\"}",
    },
    {
        "id": "invalid_imei",
        "label": "Invalid IMEI",
        "kind": "status",
        "status": 200,
        "body": "{\"status\": \"invalidimei\", \"message\": \"Invalid IMEI number provided. Please verify and try again.\"}",
    },
    {
        "id": "manual_review",
        "label": "Manual review",
        "kind": "submit",
        "status": 200,
        "body": "{\"status\": \"under_review\", \"message\": \"Email confirmation required. Select the link in the email within 24 hours to confirm your unlock request.\", \"requestNumber\": \"NUL123456789012\", \"confirmUrl\": \"https://www.att.com/deviceunlock/confirm?token=***\"}",
    },
    {
        "id": "temporary",
        "label": "Temporary error (5xx)",
        "kind": "status",
        "status": 503,
        "body": "service unavailable",
    },
    {
        "id": "waf",
        "label": "WAF / bot challenge",
        "kind": "status",
        "status": 403,
        "body": "We detected unusual traffic. Please verify you are human to continue.",
    },
    {
        "id": "drift",
        "label": "Endpoint drift (HTML not JSON)",
        "kind": "status",
        "status": 200,
        "body": "<!doctype html><html><head></head><body><div id=\"app\"></div></body></html>",
    },
    {
        "id": "low_conf",
        "label": "Low-confidence (no signal)",
        "kind": "submit",
        "status": 200,
        "body": "{\"message\": \"we received your submission\"}",
    },
]

DECISIONS = [
    ("approved", "APPROVED", "Portal approved the request.", "ok"),
    ("pending", "PENDING", "Accepted; in the normal processing window.", "warn"),
    ("manual_review", "MANUAL_REVIEW", "Extra human step (e.g. 24-h email link).", "warn"),
    ("rejected", "REJECTED", "Final server decision: not approved.", "err"),
    ("eligibility_failed", "ELIGIBILITY_FAILED", "Portal pre-check: not eligible (yet).", "err"),
    ("invalid_imei", "INVALID_IMEI", "IMEI malformed / unrecognized.", "err"),
    ("temporary_error", "TEMPORARY_ERROR", "No decision made (5xx, 429, challenge, drift).", "warn"),
]

WORKFLOW = [
    ("0. Landing", "GET /deviceunlock/", "Brand picker + published unlock requirements", "CONFIRMED"),
    ("1. Start request", "GET /deviceunlock/unlockstep1", "“Do you have a mobile number? Yes/No”, phone, consent", "CONFIRMED"),
    ("2. Device identity", "step 2 (SPA, client-rendered)", "IMEI (+email) for non-customers; phone for customers", "INFERRED"),
    ("3. Confirmation", "email", "Request number (NUL…) + 24-h confirmation link", "DOCUMENTED"),
    ("4. Decision", "email (≤ 2 business days)", "Approval email: code (Android) / remote unlock (iPhone)", "DOCUMENTED"),
    ("5. Status lookup", "GET /deviceunlock/status", "Form fields: IMEI + Request number", "CONFIRMED"),
]

ENDPOINTS = [
    ("E1", "GET", "/deviceunlock/", "SPA shell + landing", "CONFIRMED"),
    ("E2", "GET", "/deviceunlock/unlockstep1", "Step-1 form", "CONFIRMED"),
    ("E3", "GET", "/deviceunlock/status", "Status form (IMEI + request no.)", "CONFIRMED"),
    ("E4", "GET", "/wireless/imei-finder/", "Official IMEI finder", "CONFIRMED"),
    ("E5", "POST", "/deviceunlock/api/eligibility", "Eligibility pre-check (IMEI)", "INFERRED"),
    ("E6", "POST", "/deviceunlock/api/request", "Submit unlock request", "INFERRED"),
    ("E7", "GET", "/deviceunlock/api/status?imei=&requestNumber=", "Status lookup", "INFERRED"),
    ("E8", "GET/POST", "/acctmgmt/login", "MyAT&T login (cookie mode avoids it)", "INFERRED"),
]

REQUIREMENTS = [
    "Device purchased 60+ days ago (12 months prepaid), not active on another AT&T account",
    "Device paid in full — installment balance zero",
    "Device not reported lost, stolen, or fraud-involved",
    "Account current (no past-due balance) for current customers",
    "Business: service commitment ended · Military: separate documented path",
]


def _derive_eligible(decision: Decision):
    if decision == Decision.APPROVED:
        return True
    if decision in (Decision.ELIGIBILITY_FAILED, Decision.REJECTED, Decision.INVALID_IMEI):
        return False
    return None


def _run_diagnose(payload: dict):
    status = int(payload.get("status", 200) or 200)
    body = str(payload.get("body", "") or "")
    imei = str(payload.get("imei", "") or "")
    request_id = str(payload.get("request_id", "") or "")
    kind = str(payload.get("kind", "status") or "status")

    resp = RawResponse(status=status, headers={}, body=body, url="local://demo", elapsed_ms=0)
    cls = classify_response(resp)

    base = dict(
        message=cls.message,
        confidence=cls.confidence,
        matched=cls.matched,
        request_id=cls.request_id or (request_id or None),
    )
    if kind == "submit":
        result = SubmitResult(decision=cls.decision, imei=imei, **base)
        if cls.decision == Decision.MANUAL_REVIEW or "confirm" in (cls.message or "").lower():
            result.email_confirmation_required = True
    elif kind == "eligibility":
        result = EligibilityResult(
            decision=cls.decision, eligible=_derive_eligible(cls.decision), imei=imei, **base
        )
    else:
        result = StatusResult(decision=cls.decision, imei=imei, **base)

    findings = diagnose(result, raw_text=body)
    out = {
        "decision": cls.decision.value,
        "message": cls.message,
        "confidence": cls.confidence,
        "matched": cls.matched,
        "request_id": base["request_id"],
    }
    out["diagnostics"] = [f.to_dict() for f in findings]
    return out


def _run_imei(payload: dict):
    raw = str(payload.get("imei", "") or "")
    cleaned = clean_imei(raw)
    ok, reason = validate_imei(raw)
    return {
        "raw": raw,
        "cleaned": cleaned,
        "ok": ok,
        "reason": reason,
        "luhn": luhn_check(cleaned) if len(cleaned) == 15 else None,
    }


HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root{
    --bg:#0b0f14; --panel:#121824; --panel2:#0f1520; --line:#1f2a3a;
    --txt:#e6edf3; --muted:#8b98a9; --accent:#4f9cff; --accent2:#7ee0a3;
    --ok:#2ea06a; --warn:#c99a2e; --err:#e0574f; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
  header{position:sticky;top:0;z-index:5;background:rgba(11,15,20,.92);backdrop-filter:blur(6px);
         border-bottom:1px solid var(--line);padding:14px 20px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;}
  header .logo{font-weight:700;font-size:17px;letter-spacing:.2px}
  header .tag{font-size:12px;color:var(--muted)}
  header .scope{margin-left:auto;font-size:12px;color:var(--warn);border:1px solid #3a3320;
                background:#241f10;padding:4px 10px;border-radius:999px}
  nav{display:flex;gap:6px;padding:12px 20px 0;flex-wrap:wrap}
  nav button{background:transparent;border:1px solid var(--line);color:var(--muted);
             padding:7px 14px;border-radius:8px 8px 0 0;cursor:pointer;font-size:13.5px}
  nav button.active{color:var(--txt);background:var(--panel);border-bottom-color:var(--panel)}
  main{padding:18px 20px 60px;max-width:1080px;margin:0 auto}
  section{display:none}
  section.active{display:block}
  h2{font-size:20px;margin:6px 0 4px}
  h3{font-size:15px;margin:20px 0 8px;color:var(--accent2)}
  p{color:#c4cedb}
  .muted{color:var(--muted)}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0}
  .grid{display:grid;gap:14px}
  .grid.two{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
  table{width:100%;border-collapse:collapse;font-size:13.5px}
  th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
  code,.mono{font-family:var(--mono);font-size:12.5px}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:600}
  .pill.CONFIRMED{background:#12301f;color:var(--ok);border:1px solid #1c4a2f}
  .pill.DOCUMENTED{background:#12283c;color:var(--accent);border:1px solid #1d3c5c}
  .pill.INFERRED{background:#2a2312;color:var(--warn);border:1px solid #4a3c1c}
  .req-list li{margin:6px 0}
  .req-list li::marker{color:var(--accent2)}
  /* console */
  .presets{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
  .presets button{background:var(--panel2);border:1px solid var(--line);color:#c4cedb;
                  padding:6px 11px;border-radius:8px;cursor:pointer;font-size:12.5px}
  .presets button:hover{border-color:var(--accent);color:var(--txt)}
  label{font-size:12.5px;color:var(--muted);display:block;margin:10px 0 4px}
  input[type=text],textarea,select{width:100%;background:#0a0f16;border:1px solid var(--line);
      color:var(--txt);border-radius:8px;padding:9px 11px;font-family:var(--mono);font-size:13px}
  textarea{min-height:120px;resize:vertical;line-height:1.5}
  input:focus,textarea:focus,select:focus{outline:none;border-color:var(--accent)}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row>div{flex:1;min-width:160px}
  .btn{background:var(--accent);color:#04101f;border:none;padding:10px 16px;border-radius:9px;
       font-weight:700;cursor:pointer;font-size:14px;margin-top:14px}
  .btn:hover{filter:brightness(1.08)}
  .btn.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);font-weight:600}
  .decision-banner{display:flex;align-items:center;gap:12px;padding:14px 16px;border-radius:10px;
      margin:16px 0 6px;border:1px solid var(--line);background:var(--panel2)}
  .decision-banner .big{font-family:var(--mono);font-weight:800;font-size:20px;letter-spacing:.5px}
  .d-ok{box-shadow:inset 3px 0 0 var(--ok)} .d-warn{box-shadow:inset 3px 0 0 var(--warn)} .d-err{box-shadow:inset 3px 0 0 var(--err)}
  .kv{font-size:12.5px;color:var(--muted);margin-top:4px}
  .chip{display:inline-block;font-family:var(--mono);font-size:11px;background:#0a0f16;
        border:1px solid var(--line);border-radius:6px;padding:2px 7px;margin:2px 4px 2px 0;color:#aeb9c9}
  .diag{border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:12px 14px;margin:10px 0;background:var(--panel2)}
  .diag.info{border-left-color:var(--accent)} .diag.warning{border-left-color:var(--warn)} .diag.error{border-left-color:var(--err)}
  .diag .code{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .diag .title{font-weight:700;margin:2px 0}
  .diag .detail{color:#c4cedb;font-size:13.5px}
  .diag ul{margin:8px 0 0;padding-left:18px}
  .diag li{font-size:13px;color:#aeb9c9;margin:3px 0}
  .legend .item{display:flex;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}
  .legend .dot{width:10px;height:10px;border-radius:50%;margin-top:5px;flex:none}
  .footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);margin-top:30px;padding-top:16px}
  .notice{background:#241f10;border:1px solid #4a3c1c;color:#e0c48a;border-radius:10px;padding:12px 14px;font-size:13px;margin:12px 0}
  pre{background:#0a0f16;border:1px solid var(--line);border-radius:10px;padding:12px 14px;
      overflow:auto;font-family:var(--mono);font-size:12.5px;color:#c9d4e2}
  .hidden{display:none}
</style>
</head>
<body>
<header>
  <div class="logo">📡 att_unlock</div>
  <div class="tag">AT&amp;T Device Unlock portal · authorized single-account research client</div>
  <div class="scope">scope: own account · passive · no live calls</div>
</header>

<nav id="nav">
  <button data-tab="overview" class="active">Overview</button>
  <button data-tab="diagnose">Diagnostic console</button>
  <button data-tab="workflow">Workflow &amp; endpoints</button>
  <button data-tab="imei">IMEI checker</button>
  <button data-tab="security">Security notes</button>
</nav>

<main>
  <!-- OVERVIEW -->
  <section id="overview" class="active">
    <h2>Overview</h2>
    <p class="muted">A stdlib-only Python client that reproduces the <em>legitimate, single-account</em>
       workflow of AT&amp;T's official Device Unlock portal: eligibility pre-check, request submission,
       status lookup, and a rejection/decision diagnostics engine. 120 offline unit tests.</p>

    <div class="notice">
      ⚠️ This demo is <strong>entirely local</strong>. The console below runs the real
      <code>att_unlock</code> parser + diagnostics over a response you paste (or pick from a synthetic
      preset). <strong>No request is sent to AT&amp;T or any external host</strong> — this sandbox has no
      egress, and none is attempted.
    </div>

    <h3>What the brief asked vs. what was built (scope guardrails)</h3>
    <div class="grid two">
      <div class="card">
        <h3 style="margin-top:0">✅ Built</h3>
        <p style="font-size:13.5px;margin:6px 0">
          • Endpoint &amp; workflow map (confirmed vs. inferred)<br>
          • 7-state response classifier + request-id / confirm-link extraction<br>
          • Rejection-diagnostic engine (online + offline <code>--json-file</code>)<br>
          • Cookie-mode / human-MFA login (secrets never logged)<br>
          • Human-pace gates: no POST auto-retry, honors <code>Retry-After</code>, 300s min interval
        </p>
      </div>
      <div class="card">
        <h3 style="margin-top:0">🚫 Deliberately not built</h3>
        <p style="font-size:13.5px;margin:6px 0">
          • No assumption that a “clean IMEI” guarantees eligibility (it doesn't)<br>
          • No reverse-engineering / probing of the server-side decision boundary<br>
          • No PoC exploit, MFA bypass, forgery, rate-limit circumvention, or
            rejection→approval mutation<br>
          • Rejections are <strong>final</strong> in code — never re-framed or auto-resubmitted
        </p>
      </div>
    </div>

    <h3>The seven normalized decisions</h3>
    <div class="card legend" id="legend"></div>

    <h3>Quick start</h3>
    <pre>python3 -m att_unlock calibrate
python3 -m att_unlock eligibility --imei 35XXXXXXXXXXXXX
python3 -m att_unlock submit --imei 35XXXXXXXXXXXXX --customer yes
python3 -m att_unlock status --request-id NULXXXXXXXXXXX --imei 35XXXXXXXXXXXXX
python3 -m att_unlock diagnose --request-id NULXXXXXXXXXXX --imei 35XXXXXXXXXXXXX
python3 -m unittest discover -s att_unlock/tests -t .   # 120 tests, offline</pre>
  </section>

  <!-- DIAGNOSE -->
  <section id="diagnose">
    <h2>Diagnostic console</h2>
    <p class="muted">Paste a portal response (HTTP status + body) and the real
       <code>classify_response()</code> + <code>diagnose()</code> run in-process.
       Pick a preset or type your own.</p>

    <div class="card">
      <div class="presets" id="presets"></div>

      <div class="row">
        <div>
          <label>HTTP status</label>
          <input type="text" id="d-status" value="200" inputmode="numeric">
        </div>
        <div>
          <label>Result kind</label>
          <select id="d-kind">
            <option value="status">status lookup</option>
            <option value="submit">submit response</option>
            <option value="eligibility">eligibility pre-check</option>
          </select>
        </div>
        <div>
          <label>IMEI (optional, context)</label>
          <input type="text" id="d-imei" placeholder="35XXXXXXXXXXXXX">
        </div>
        <div>
          <label>Request id (optional, context)</label>
          <input type="text" id="d-req" placeholder="NULXXXXXXXXXXX">
        </div>
      </div>

      <label>Response body (JSON or text)</label>
      <textarea id="d-body" spellcheck="false"></textarea>

      <button class="btn" id="d-run">▶ Run diagnostics</button>
      <button class="btn ghost" id="d-clear">Clear</button>
    </div>

    <div id="d-out"></div>
  </section>

  <!-- WORKFLOW -->
  <section id="workflow">
    <h2>Workflow &amp; endpoint map</h2>
    <p class="muted">Passive research, 2026-09-09. Every row is labeled: what was
       <span class="pill CONFIRMED">CONFIRMED</span> on the public site, what's
       <span class="pill DOCUMENTED">DOCUMENTED</span> by AT&amp;T, and what is
       <span class="pill INFERRED">INFERRED</span> (calibratable, never asserted).</p>

    <div class="card">
      <h3 style="margin-top:0">Browser workflow</h3>
      <table>
        <thead><tr><th>Step</th><th>Where</th><th>What</th><th>Status</th></tr></thead>
        <tbody id="wf-body"></tbody>
      </table>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Endpoint map</h3>
      <table>
        <thead><tr><th>#</th><th>Method</th><th>Path</th><th>Purpose</th><th>Status</th></tr></thead>
        <tbody id="ep-body"></tbody>
      </table>
      <p class="kv">E5–E8 and their JSON field names are <span class="pill INFERRED">INFERRED</span> —
         calibrate them in an authorized browser session (DevTools → XHR) before live use.</p>
    </div>

    <div class="card">
      <h3 style="margin-top:0">Published eligibility requirements (why “clean IMEI” ≠ eligible)</h3>
      <ul class="req-list" id="req-list"></ul>
    </div>
  </section>

  <!-- IMEI -->
  <section id="imei">
    <h2>IMEI checker</h2>
    <p class="muted">Runs the real <code>validate_imei()</code> + Luhn check. A Luhn mismatch is a
       <em>soft warning</em> (some legit devices carry non-Luhn IMEIs) — it never blocks; the portal is
       the final word. Not an eligibility check.</p>
    <div class="card">
      <label>IMEI (spaces/dashes ok — they're stripped)</label>
      <input type="text" id="i-imei" placeholder="35 1234 5678 9012 3" style="text-transform:uppercase">
      <button class="btn" id="i-run">Check IMEI</button>
      <div id="i-out" style="margin-top:14px"></div>
    </div>
  </section>

  <!-- SECURITY -->
  <section id="security">
    <h2>Security notes (passive only)</h2>
    <div class="notice">
      <strong>Method:</strong> passive observation only — public-page fetches, AT&amp;T-published docs,
      and public third-party captures. <strong>No authenticated calls, no POSTs, no probing, no fuzzing,
      no exploitation.</strong> No PoC exploit code exists in this repository by design. Active testing of
      AT&amp;T production requires their explicit written authorization; any suspected vulnerability goes
      through their responsible-disclosure channel.
    </div>
    <div class="card" id="sec-body"></div>
  </section>

  <div class="footer">
    att_unlock · research build · stdlib-only · all classification shown is offline and local.
    Nothing here grants, alters, or bypasses any AT&amp;T decision.
  </div>
</main>

<script>
const $=(s)=>document.querySelector(s);
const PRESETS=__PRESETS__;
const DECISIONS=__DECISIONS__;
const WORKFLOW=__WORKFLOW__;
const ENDPOINTS=__ENDPOINTS__;
const REQUIREMENTS=__REQUIREMENTS__;

const SECURITY=[
 ["S1","Status lookup is keyed by (IMEI + request number), not by session",
  "The public status form says “all you need is your device IMEI and unlock request number.” The number is issued in the confirmation email — possession of that email is the lookup credential (documented design). Implication: anyone who compromises the confirmation email and knows the IMEI can track the request's state, including approval. Control = email confidentiality; the client never writes request numbers to disk.",
  "info"],
 ["S2","Eligibility pre-check sits in the public, pre-login flow",
  "The non-customer path starts from an IMEI + email before any account verification. If the pre-check discloses coarse eligibility state keyed only by IMEI, that state is queryable by anyone holding an IMEI (a low-cost identifier). By-design consumer functionality, noted because IMEs are cheap to obtain.",
  "info"],
 ["S3","Edge protection / bot management",
  "TLS resets were observed to non-browser clients from a datacenter network; the site is a hash-routed SPA behind edge tooling. The client detects challenge responses (403/429/503 + known wording) and reports them as temporary_error + DX_WAF_CHALLENGE. No bypass technique is implemented or suggested.",
  "info"],
 ["S4","Confirmation link acts as a bearer token",
  "The 24-hour email-confirmation link confirms the request for whoever clicks it. Treat the confirmation email as credential-equivalent: don't forward it, don't paste the link into shared channels. The client surfaces the link only in the operator's own terminal and warns to keep it private.",
  "warning"],
 ["S5","CSRF handling (inferred, unverified live)",
  "The SPA is expected to carry a CSRF token (cookie/meta/JSON). The client extracts all three patterns and sends it on state-changing requests; whether the live API enforces it is a calibration/authorized-test question, not something this project tests.",
  "info"],
 ["S6","Rate limiting is honored, never circumvented",
  "429/503 + Retry-After → capped sleep, GETs only; plus a local minimum interval between submissions (default 5 min) and no automatic POST retries. No proxy rotation, account multiplexing, or request flooding exists anywhere in the repo.",
  "info"],
];

function pill(t){return `<span class="pill ${t}">${t}</span>`;}

function renderLegend(){
  $("#legend").innerHTML=DECISIONS.map(([v,name,desc,cls])=>{
    const color=cls==="ok"?"var(--ok)":cls==="err"?"var(--err)":"var(--warn)";
    return `<div class="item"><span class="dot" style="background:${color}"></span>
      <div><code>${name}</code> <span class="muted">· ${v}</span><br>
      <span class="muted" style="font-size:13px">${desc}</span></div></div>`;
  }).join("");
}
function renderWorkflow(){
  $("#wf-body").innerHTML=WORKFLOW.map(([s,w,wh,st])=>
    `<tr><td>${s}</td><td class="mono">${w}</td><td>${wh}</td><td>${pill(st)}</td></tr>`).join("");
  $("#ep-body").innerHTML=ENDPOINTS.map(([n,m,p,pu,st])=>
    `<tr><td>${n}</td><td class="mono">${m}</td><td class="mono">${p}</td><td>${pu}</td><td>${pill(st)}</td></tr>`).join("");
  $("#req-list").innerHTML=REQUIREMENTS.map(r=>`<li>${r}</li>`).join("");
}
function renderSecurity(){
  $("#sec-body").innerHTML=SECURITY.map(([id,t,d,sev])=>
    `<div class="diag ${sev}"><div class="code">${id}</div><div class="title">${t}</div>
     <div class="detail">${d}</div></div>`).join("");
}

// tabs
document.querySelectorAll("#nav button").forEach(b=>{
  b.addEventListener("click",()=>{
    document.querySelectorAll("#nav button").forEach(x=>x.classList.remove("active"));
    document.querySelectorAll("main section").forEach(x=>x.classList.remove("active"));
    b.classList.add("active");
    $("#"+b.dataset.tab).classList.add("active");
  });
});

// presets
$("#presets").innerHTML=PRESETS.map(p=>
  `<button data-id="${p.id}">${p.label}</button>`).join("");
document.querySelectorAll("#presets button").forEach(btn=>{
  btn.addEventListener("click",()=>{
    const p=PRESETS.find(x=>x.id===btn.dataset.id);
    $("#d-status").value=p.status;
    $("#d-kind").value=p.kind;
    $("#d-body").value=p.body;
    runDiagnose();
  });
});
$("#d-run").addEventListener("click",runDiagnose);
$("#d-clear").addEventListener("click",()=>{
  $("#d-status").value="200";$("#d-kind").value="status";
  $("#d-imei").value="";$("#d-req").value="";$("#d-body").value="";$("#d-out").innerHTML="";
});

function esc(s){return (s||"").replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));}

function decisionClass(d){
  if(d==="approved")return "ok";
  if(d==="rejected"||d==="eligibility_failed"||d==="invalid_imei")return "err";
  return "warn";
}
function renderDiagnose(r){
  const cls=decisionClass(r.decision);
  const label=r.decision.replace(/_/g," ").toUpperCase();
  let html=`<div class="decision-banner d-${cls}">
     <div><div class="big" style="color:var(${cls==="ok"?"--ok":cls==="err"?"--err":"--warn"})">${label}</div>
     <div class="kv">confidence: ${r.confidence} · request id: ${esc(r.request_id||"—")}</div></div>
   </div>`;
  if(r.message)html+=`<p class="muted" style="font-size:13.5px">${esc(r.message)}</p>`;
  if(r.matched&&r.matched.length)
    html+=`<div>${r.matched.map(m=>`<span class="chip">${esc(m)}</span>`).join("")}</div>`;
  html+=`<h3>Diagnostics (${(r.diagnostics||[]).length})</h3>`;
  (r.diagnostics||[]).forEach(d=>{
    html+=`<div class="diag ${d.severity}">
      <div class="code">${esc(d.code)}</div>
      <div class="title">${esc(d.title)}</div>
      <div class="detail">${esc(d.detail)}</div>`;
    if(d.actions&&d.actions.length)
      html+=`<ul>${d.actions.map(a=>`<li>${esc(a)}</li>`).join("")}</ul>`;
    if(d.references&&d.references.length)
      html+=`<div class="kv" style="margin-top:8px">${d.references.map(x=>`<span class="chip">${esc(x)}</span>`).join("")}</div>`;
    html+=`</div>`;
  });
  $("#d-out").innerHTML=html;
}

async function runDiagnose(){
  const payload={
    status:$("#d-status").value||"200",
    kind:$("#d-kind").value,
    imei:$("#d-imei").value,
    request_id:$("#d-req").value,
    body:$("#d-body").value,
  };
  $("#d-out").innerHTML=`<p class="muted">…</p>`;
  try{
    const res=await fetch("/api/diagnose",{method:"POST",
      headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const data=await res.json();
    if(data.error)throw new Error(data.error);
    renderDiagnose(data);
  }catch(e){
    $("#d-out").innerHTML=`<div class="diag error"><div class="title">Error</div>
      <div class="detail">${esc(e.message)}</div></div>`;
  }
}

// IMEI
$("#i-run").addEventListener("click",checkImei);
$("#i-imei").addEventListener("keydown",e=>{if(e.key==="Enter")checkImei();});
async function checkImei(){
  const imei=$("#i-imei").value;
  try{
    const res=await fetch("/api/imei",{method:"POST",
      headers:{"Content-Type":"application/json"},body:JSON.stringify({imei})});
    const d=await res.json();
    if(d.error)throw new Error(d.error);
    const cls=d.ok?(d.luhn===false?"warn":"ok"):"err";
    const word=d.ok?(d.luhn===false?"OK (Luhn warning)":"VALID"):"INVALID";
    let extra="";
    if(d.luhn===true)extra=`<span class="chip" style="color:var(--ok)">luhn ✓</span>`;
    else if(d.luhn===false)extra=`<span class="chip" style="color:var(--warn)">luhn ✗ (soft warning — may still be a real IMEI)</span>`;
    $("#i-out").innerHTML=`
      <div class="decision-banner d-${cls}">
        <div><div class="big" style="color:var(${cls==="ok"?"--ok":cls==="err"?"--err":"--warn"})">${word}</div>
        <div class="kv">cleaned: <code>${esc(d.cleaned)||"—"}</code></div></div>
      </div>
      <p class="muted" style="font-size:13.5px">${esc(d.reason)}</p>${extra}
      <p class="kv">This is a <em>format/Luhn</em> check only — not an eligibility decision.</p>`;
  }catch(e){
    $("#i-out").innerHTML=`<div class="diag error"><div class="detail">${esc(e.message)}</div></div>`;
  }
}

renderLegend();renderWorkflow();renderSecurity();
</script>
</body>
</html>
"""


def build_html() -> str:
    return (
        HTML.replace("__TITLE__", TITLE)
        .replace("__PRESETS__", json.dumps(PRESETS))
        .replace("__DECISIONS__", json.dumps(DECISIONS))
        .replace("__WORKFLOW__", json.dumps(WORKFLOW))
        .replace("__ENDPOINTS__", json.dumps(ENDPOINTS))
        .replace("__REQUIREMENTS__", json.dumps(REQUIREMENTS))
    )


PAGE = build_html()


class Handler(BaseHTTPRequestHandler):
    server_version = "attunlock-demo/1.0"

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path == "/api/presets":
            self._json({"presets": PRESETS, "decisions": DECISIONS})
        elif self.path == "/healthz":
            self._json({"ok": True})
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):  # noqa: N802
        try:
            if self.path == "/api/diagnose":
                self._json(_run_diagnose(self._read_json()))
            elif self.path == "/api/imei":
                self._json(_run_imei(self._read_json()))
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")
        except Exception as err:  # noqa: BLE001 - report, never crash the server
            self._json({"error": f"internal error: {err}"}, code=500)

    def log_message(self, fmt, *args):  # quiet, one line per request
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"att_unlock demo on http://{args.host}:{args.port} (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
