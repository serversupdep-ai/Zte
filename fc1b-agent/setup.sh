#!/usr/bin/env bash
# Build the FC1B Unlock Agent from this bundle (Agent-Me framework + this session's files).
set -euo pipefail
cd "$(dirname "$0")"

# 1. Fetch the Agent-Me framework
if [ ! -d agent-me ]; then
  git clone --depth 1 https://github.com/jzjzzzzzzz/agent-me.git agent-me
fi
cd agent-me

# 2. Drop this session's knowledge, tools and docs into it
rm -f knowledge/example-profile.md
cp -r ../knowledge/. knowledge/
cp -r ../tools/. tools/
cp ../FC1B-AGENT.md ../SUFFIX-CHEATSHEET.md .
cp ../agent.env .env

# 3. Frontend preview-host fix (Vite 6): allow proxied hosts
python3 - <<'EOF'
from pathlib import Path
p = Path("frontend/vite.config.ts")
t = p.read_text()
if "allowedHosts" not in t:
    t = t.replace("  server: {", "  server: {\n    host: \"0.0.0.0\",\n    allowedHosts: true,")
    p.write_text(t)
EOF

# 4. Backend deps
python3 -m venv venv
./venv/bin/pip install fastapi "uvicorn[standard]" pydantic-settings httpx

# 5. Frontend deps
(cd frontend && npm ci)

# 6. Self-test the tools
./venv/bin/python tools/test_fc1b_tools.py

echo
echo "Agent ready. Start it with:"
echo "  ./venv/bin/python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 &"
echo "  (cd frontend && npm run dev) &"
echo "  Web UI: http://localhost:5173  |  API docs: http://localhost:8000/docs"
