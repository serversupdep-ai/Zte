"""FC1B toolkit API — makes the agent a doer, not just a talker.

Endpoints:
  GET  /api/v1/tools        — list available tools
  POST /api/v1/tools/run    — execute an allowlisted tool

  Tools: keygen, hunt, classify, unlock-analyze, selftest

Also provides augment_answer(question, answer): detects "<tag>-<suffix>"
questions in chat and appends the live keygen output to the knowledge answer.
"""
from __future__ import annotations

import base64
import binascii
import os
import re
import subprocess
import tempfile
import time

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1/tools", tags=["tools"])

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TOOLS_DIR = os.path.join(AGENT_ROOT, "tools")
HUNT_DIR = "/home/user/Zte/ec-hunt" if os.path.isdir("/home/user/Zte/ec-hunt") else TOOLS_DIR
PY = os.path.join(AGENT_ROOT, "venv", "bin", "python")
if not os.path.exists(PY):
    PY = "python3"

SUFFIXES = {"595B", "D35B", "2A7B", "A95B", "1D3B", "1F5A", "1F66", "6FF1",
            "BF97", "E7A8", "8FC8", "CF1B", "FC1B", "1B58", "9ABE", "3FE2", "A6E0"}
TAG_RE = re.compile(r"^[A-Z0-9]{7}$")
SUFFIX_RE = re.compile(r"^[A-Z0-9]{4}$")
TAGQ_RE = re.compile(
    r"\b([A-Z0-9]{7})\s*[-:\s]?\s*(595B|D35B|2A7B|A95B|1D3B|1F5A|1F66|6FF1|"
    r"BF97|E7A8|8FC8|CF1B|FC1B|1B58|9ABE|3FE2|A6E0)\b", re.I)

TOOLS = [
    {"name": "keygen", "description": "Compute Dell master-password candidates for a service tag + suffix (48 families incl. CF1B firmware path)",
     "args": {"tag": "7-char service tag, e.g. CVZKKD3", "suffix": "4-char family, e.g. CF1B"}},
    {"name": "hunt", "description": "Run the ec-hunt fetch sweep for new public EC-firmware/dump files (GitHub sources)",
     "args": {"max": "max files to fetch (default 20, max 60)"}},
    {"name": "classify", "description": "Classify a firmware/dump file (base64) — sealed / plaintext / GENERATE-engine hit",
     "args": {"name": "filename", "data_b64": "base64 file content (max 8 MB)"}},
    {"name": "unlock-analyze", "description": "Analyze a Dell SPI dump (base64) for the EC record store / lock markers",
     "args": {"name": "filename", "data_b64": "base64 dump content (max 40 MB)"}},
    {"name": "selftest", "description": "Run the toolkit self-tests (legacy keygen + unlocker vectors)", "args": {}},
]


def _run(argv: list[str], timeout: int, cwd: str = AGENT_ROOT) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        return {"ok": p.returncode == 0, "exit_code": p.returncode,
                "stdout": p.stdout[-8000:], "stderr": p.stderr[-4000:],
                "duration_ms": int((time.time() - t0) * 1000)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit_code": -1, "stdout": "",
                "stderr": f"tool timed out after {timeout}s", "duration_ms": int((time.time() - t0) * 1000)}
    except Exception as e:  # pragma: no cover
        return {"ok": False, "exit_code": -1, "stdout": "", "stderr": str(e)[:500],
                "duration_ms": int((time.time() - t0) * 1000)}


@router.get("")
async def list_tools() -> dict:
    return {"tools": TOOLS, "hunt_dir": HUNT_DIR}


@router.post("/run")
async def run_tool(payload: dict) -> dict:
    tool = payload.get("tool", "")
    args = payload.get("args", {}) or {}
    result = {"tool": tool, "ok": False, "stdout": "", "stderr": "unknown tool"}

    if tool == "keygen":
        tag = str(args.get("tag", "")).upper().strip()
        suffix = str(args.get("suffix", "")).upper().strip()
        if not TAG_RE.match(tag) or not SUFFIX_RE.match(suffix):
            result["stderr"] = "tag must be 7 alphanumerics, suffix 4 alphanumerics"
            return result
        result = _run([PY, os.path.join(TOOLS_DIR, "dell_keygen48.py"), tag, suffix], 60)
        result["tool"] = tool
        return result

    if tool == "hunt":
        try:
            mx = min(max(int(args.get("max", 20)), 1), 60)
        except (TypeError, ValueError):
            mx = 20
        result = _run([PY, os.path.join(HUNT_DIR, "ec_hunt.py"), "--max", str(mx)], 420,
                      cwd=HUNT_DIR)
        result["tool"] = tool
        return result

    if tool == "classify":
        blob, err = _decode(args, 8 * 1024 * 1024)
        if err:
            result["stderr"] = err
            return result
        name, data = blob
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(name)[1] or ".bin",
                                         delete=False) as f:
            f.write(data)
            tmp = f.name
        try:
            r = _run([PY, os.path.join(TOOLS_DIR, "ec_classify.py"), tmp], 120)
        finally:
            os.unlink(tmp)
        r["tool"] = tool
        return r

    if tool == "unlock-analyze":
        blob, err = _decode(args, 40 * 1024 * 1024)
        if err:
            result["stderr"] = err
            return result
        name, data = blob
        with tempfile.NamedTemporaryFile(suffix=os.path.splitext(name)[1] or ".bin",
                                         delete=False) as f:
            f.write(data)
            tmp = f.name
        try:
            r = _run([PY, os.path.join(TOOLS_DIR, "dell_unlock_image.py"), "--analyze", tmp], 180)
        finally:
            os.unlink(tmp)
        r["tool"] = tool
        return r

    if tool == "selftest":
        result = _run([PY, os.path.join(TOOLS_DIR, "test_fc1b_tools.py")], 120)
        result["tool"] = tool
        return result

    return result


def _decode(args: dict, cap: int) -> tuple[tuple[str, bytes], str | None]:
    name = str(args.get("name", "upload.bin"))[:120]
    b64 = str(args.get("data_b64", ""))
    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return (("", b""), "invalid base64")
    if not data or len(data) > cap:
        return (("", b""), f"data empty or exceeds {cap // (1024 * 1024)} MB cap")
    return ((name, data), None)


def keygen_for(tag: str, suffix: str) -> str:
    r = _run([PY, os.path.join(TOOLS_DIR, "dell_keygen48.py"), tag, suffix], 60)
    return r["stdout"].strip() if r["ok"] and r["stdout"].strip() else ""


def augment_answer(question: str, answer: str) -> str:
    """If the question contains <service-tag>-<suffix>, run the live keygen and
    prepend the computed output to the knowledge-grounded answer."""
    m = TAGQ_RE.search(question)
    if not m:
        return answer
    tag, suffix = m.group(1).upper(), m.group(2).upper()
    out = keygen_for(tag, suffix)
    if not out:
        return answer
    return (f"**Live tool run — `dell_keygen48.py {tag} {suffix}`:**\n```\n{out}\n```\n\n"
            f"(Try candidates at the lock screen with Ctrl+Enter+Enter; on latest "
            f"firmware use the EC readout — see knowledge below.)\n\n{answer}")
