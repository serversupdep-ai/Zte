# FC1B Unlock Agent

A purpose-built [Agent-Me](https://github.com/jzjzzzzzzz/agent-me) twin for one task:
**decrypting / clearing Dell BIOS master passwords**, specialized for the
**FC1B / CF1B / 8FC8** firmware-lock family, plus legacy-suffix master password
generation (595B, 2A7B, A95B, D35B, 1D3B, 1F5A, 1F66, 6FF1, BF97, E7A8).

**Active case:** Dell **Precision 3640 Tower**, service tag `CVZKKD3-CF1B`
(Express Service Code 28055585559).

## Key facts baked into the agent's knowledge

- **FC1B (also written CF1B)** is the newest Dell BIOS password suffix (successor
  to 8FC8, ~2023+ Latitude/Precision machines).
- **No public service-tag → master-password algorithm exists for FC1B/CF1B/8FC8.**
  The password is verified inside the firmware, so keygens cannot produce it.
- Two real routes: **official Dell support unlock** (proof of ownership) or
  **BIOS dump patching** (dump full SPI flash → zero the `00FCAA` system and
  `00FDAA` admin password entries → flash back → re-enter service tag).
- Dell NVRAM stores **four redundant password verification flags** — all must be
  zeroed; after flashing, the board starts in Manufacturing Mode and ignores the
  old password.

## Layout

```
knowledge/                       # the agent's brain (Markdown docs)
  dell-fc1b-master-password.md   # what FC1B is + the two routes
  fc1b-bios-patch-procedure.md   # 5-step dump/patch/flash procedure
  dell-suffix-keygen-reference.md# legacy suffix keygen usage + quirks
  troubleshooting-and-safety.md  # failure modes, legality, scope limits
  workspace-and-tools.md         # agent identity + companion tools
  case-cvzkkd3-cf1b.md           # active case status
tools/
  dell_fc1b_unlock.py            # scan/patch an FC1B|CF1B|8FC8 BIOS dump
  dell_keygen.py                 # legacy-suffix master password generator
  test_fc1b_tools.py             # self-tests (all passing)
.env                             # APP_NAME / knowledge config
```

## Run it

```bash
# backend (FastAPI) — port 8000
/home/user/agent-me/venv/bin/python -m uvicorn app.main:app \
  --app-dir /home/user/agent-me/backend --host 0.0.0.0 --port 8000 &

# frontend (Vite) — port 5173, proxies /api to the backend
cd /home/user/agent-me/frontend && npm run dev &

# API docs: http://localhost:8000/docs
# Endpoints: POST /api/v1/chat | POST /api/v1/collaborate (5-stage verified workflow)
```

If dependencies are missing (fresh sandbox), rebuild them:

```bash
python3 -m venv venv && venv/bin/pip install fastapi 'uvicorn[standard]' pydantic-settings httpx
cd frontend && npm ci
```

## Use the tools

```bash
# generate a legacy-suffix master password (validated: DELLSUX-1F66 -> qHXaL0ntli6Gu4c0)
python3 tools/dell_keygen.py ABC1234-1F66

# scan only
python3 tools/dell_fc1b_unlock.py dump.bin --scan-only
# scan + patch (writes patched_dump.bin)
python3 tools/dell_fc1b_unlock.py dump.bin

# run the test suite
python3 tools/test_fc1b_tools.py
```

Knowledge edits hot-reload (the corpus is re-fingerprinted per request), so you
can extend `knowledge/` and ask new questions without restarting.

Only use these tools on machines you own or are authorized to service.
