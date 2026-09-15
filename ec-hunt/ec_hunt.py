#!/usr/bin/env python3
"""ec_hunt.py — the agent fetch tool of the CF1B offline-keygen campaign.

Sweeps sources for files that could carry the EC GENERATE engine in
plaintext (the single artifact class that completes an offline CF1B keygen
— CF1B_FINDINGS §11.7/§11.8), downloads candidates, classifies them with
ec_classify, and reports. A plaintext GENERATE-era EC image => HIT =>
ec_generate_emu.py finishes the keygen.

Sources:
  S1  sibling arena/* branches of this repo (the relay workflows commit
      fetched dumps there — re-check their output automatically)
  S2  GitHub repository search (new/updated repos matching EC-dump keywords)
  S3  watchlist.txt (one URL per line; # comments; GitHub URLs via the blob
      API from anywhere, arbitrary URLs need --allow-net e.g. on the
      Actions runner which has full egress)

Usage:
  python3 ec_hunt.py                 # GitHub-only sweep (sandbox-safe)
  python3 ec_hunt.py --allow-net     # runner: also fetch non-GitHub URLs
  python3 ec_hunt.py --max N         # cap candidate downloads (default 40)
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import io
import zipfile
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ec_classify import classify_bytes  # noqa: E402

REPO = "serversupdep-ai/Zte"
QUARANTINE = os.path.join(HERE, "quarantine")
FETCHED = os.path.join(HERE, "fetched")
SEEN = os.path.join(HERE, "seen.json")
REPORT = os.path.join(HERE, "HUNT-REPORT.md")
WATCHLIST = os.path.join(HERE, "watchlist.txt")

# URL fetches (watchlist/forum attachments) may be full 32 MB SPI dumps.
# GitHub candidates stay capped by the 8 MB filter in the source functions.
MAX_SIZE = 8 * 1024 * 1024
FETCH_MAX = 40 * 1024 * 1024
# only payloads at least this big are persisted into ec-hunt/fetched/ for the
# workflow to commit (small files are usually HTML login/redirect pages)
FETCHED_MIN = 512 * 1024

BIN_EXT = (".bin", ".rom", ".fd", ".cap", ".rcv", ".efi", ".rar", ".7z", ".zip", ".img")
NAME_RE = re.compile(r"(^|[_\-\s])(ec|ecfw|ecfirm|ec程序)|pw_[0-9]|pass[_\-\s]?\d*mb|"
                     r"8fc8|cf1b|9abe|1b58|3fe2|dump|bios|dell|"
                     r"\d+\s?mb|latitude|optiplex|precision|vostro|inspiron|"
                     r"0x[0-9a-f]{4}|phcm", re.I)


def looks_candidate(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    if "ec-hunt/" in path or base.endswith((".md", ".py", ".txt", ".yml", ".json", ".c", ".sh", ".html", ".log")):
        return False
    if "EC程序" in base:
        return True
    return base.lower().endswith(BIN_EXT) and bool(NAME_RE.search(base))

KEYWORDS = ["dell ec dump", "dell ec firmware", "EC程序 dell", "dell 8fc8",
            "dell cf1b", "dell bios dump unlock", "dell pass 8mb",
            "dell bios dump", "dell ch341a", "dell rt809h", "dell spi dump",
            "dell latitude dump", "dell optiplex dump", "dell precision dump",
            "dell bios bin", "dell ec bin", "8fc8 patcher", "dell bios password"]


def gh(*args, timeout=60):
    """gh api call -> parsed JSON, or None on failure."""
    try:
        out = subprocess.run(["gh", "api"] + list(args), capture_output=True,
                             text=True, timeout=timeout)
        if out.returncode == 0:
            return json.loads(out.stdout) if out.stdout.strip() else None
    except Exception:
        pass
    return None


def gh_raw(path_api):
    """Fetch raw bytes via the blob/contents API (works where raw.githubusercontent is blocked)."""
    try:
        out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.raw",
                              path_api], capture_output=True, timeout=120)
        if out.returncode == 0:
            return out.stdout if isinstance(out.stdout, bytes) else out.stdout.encode()
    except Exception:
        pass
    return None


def load_seen():
    try:
        with open(SEEN) as f:
            return json.load(f)
    except Exception:
        return {}


def save_seen(seen):
    with open(SEEN, "w") as f:
        json.dump(seen, f, indent=1, sort_keys=True)


# ---------------------------------------------------------------- sources
def source_sibling_branches():
    """Every arena/* branch tree; candidate files by name+size."""
    out = []
    branches = gh(f"repos/{REPO}/branches?per_page=100") or []
    for b in branches:
        name = b.get("name", "")
        if not name.startswith("arena/"):
            continue
        tree = gh(f"repos/{REPO}/git/trees/{urllib.parse.quote(name)}?recursive=1",
                  timeout=120)
        if not tree:
            continue
        for it in tree.get("tree", []):
            if it.get("type") == "blob" and looks_candidate(it.get("path", "")):
                sz = it.get("size", 0)
                if 256 <= sz <= MAX_SIZE:
                    out.append({"source": f"branch:{name}", "path": it["path"],
                                "sha": it["sha"], "size": sz})
    return out


def source_repo_search():
    """GitHub repos matching keywords; scan their default-branch trees."""
    out = []
    seen_repos = set()
    for q in KEYWORDS:
        res = gh(f"search/repositories?q={urllib.parse.quote(q)}&sort=updated&per_page=10")
        for item in (res or {}).get("items", []):
            full = item.get("full_name", "")
            if not full or full in seen_repos or full == REPO:
                continue
            seen_repos.add(full)
            tree = gh(f"repos/{full}/git/trees/HEAD?recursive=1", timeout=120)
            time.sleep(0.5)
            if not tree:
                continue
            for it in tree.get("tree", []):
                if it.get("type") == "blob" and looks_candidate(it.get("path", "")):
                    sz = it.get("size", 0)
                    if 256 <= sz <= MAX_SIZE:
                        out.append({"source": f"repo:{full}", "path": it["path"],
                                    "sha": it["sha"], "size": sz})
            # release assets (repair dumps are often attached to releases)
            rels = gh(f"repos/{full}/releases?per_page=5") or []
            for rel in rels:
                for a in rel.get("assets", []):
                    if looks_candidate(a.get("name", "")) and 256 <= a.get("size", 0) <= MAX_SIZE:
                        out.append({"source": f"release:{full}", "path": a["name"],
                                    "asset_api": f"repos/{full}/releases/assets/{a['id']}",
                                    "size": a["size"]})
            if len(seen_repos) >= 25:
                break
    return out


def source_watchlist(allow_net):
    out = []
    if not os.path.exists(WATCHLIST):
        return out
    for line in open(WATCHLIST):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", line)
        if m:
            owner, repo, ref, path = m.groups()
            out.append({"source": f"watch:{line}", "gh_path":
                        f"repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}",
                        "size": 0})
        elif allow_net:
            out.append({"source": f"watch:{line}", "url": line, "size": 0})
    return out


# ---------------------------------------------------------------- fetch+classify
def fetch(item):
    if "gh_path" in item:
        return gh_raw(item["gh_path"])
    if "sha" in item and item.get("source", "").startswith(("branch:", f"repo:")):
        owner_repo = REPO if item["source"].startswith("branch:") else item["source"][5:]
        return gh_raw(f"repos/{owner_repo}/git/blobs/{item['sha']}")
    if "asset_api" in item:
        try:
            out = subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream",
                                  item["asset_api"]], capture_output=True, timeout=120)
            if out.returncode == 0:
                return out.stdout if isinstance(out.stdout, bytes) else out.stdout.encode()
        except Exception:
            return None
        return None
    if "url" in item:
        try:
            # real-browser UA: several forums 403 the default python UA
            req = urllib.request.Request(item["url"], headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
            })
            with urllib.request.urlopen(req, timeout=180) as r:
                data = r.read(FETCH_MAX + 1)
                return data[:FETCH_MAX]
        except Exception:
            return None
    return None


def hunt(max_downloads=40, allow_net=False):
    seen = load_seen()
    candidates = []
    candidates += source_sibling_branches()
    candidates += source_repo_search()
    candidates += source_watchlist(allow_net)

    # dedupe by (sha or url), skip already-seen
    fresh, uniq = [], set()
    for c in candidates:
        key = c.get("sha") or c.get("url") or c.get("gh_path") or c["source"] + c["path"]
        if key in seen or key in uniq:
            continue
        uniq.add(key)
        c["_key"] = key
        fresh.append(c)

    results, hits, downloaded = [], [], 0
    gated = []
    os.makedirs(QUARANTINE, exist_ok=True)
    os.makedirs(FETCHED, exist_ok=True)

    def is_html(d):
        head = d[:512].lstrip().lower()
        return head.startswith(b"<!doctype html") or head.startswith(b"<html") or b"<html" in head


    def persist(name, data, sha):
        """Save a fetched payload (and, for archives, every member) into
        ec-hunt/fetched/ so the workflow commits the actual files into the
        repo — 'fetch pull files into GitHub'."""
        saved = []
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", (name or "file").split("/")[-1])[:80] or "file"
        if len(data) >= FETCHED_MIN:
            dest = os.path.join(FETCHED, f"{sha[:12]}-{safe}")
            with open(dest, "wb") as f:
                f.write(data)
            saved.append(dest)
        # archives: extract + persist + classify each member (builds*.zip etc.
        # carry the actual SPI dump inside)
        if data[:4] == b"PK\x03\x04":
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
                for info in zf.infolist():
                    if info.is_dir() or info.file_size > FETCH_MAX:
                        continue
                    mdata = zf.read(info)
                    msha = hashlib.sha256(mdata).hexdigest()
                    if msha in seen:
                        continue
                    seen[msha] = True
                    mr = classify_bytes(mdata, f"{info.filename} (archive: {name})")
                    mr["sha256"] = msha
                    results.append(mr)
                    if mr["hit"]:
                        hits.append(mr)
                        hsafe = re.sub(r"[^A-Za-z0-9_.-]", "_", info.filename.split("/")[-1])[:80]
                        with open(os.path.join(QUARANTINE, f"HIT-{msha[:12]}-{hsafe}"), "wb") as f:
                            f.write(mdata)
                    if len(mdata) >= FETCHED_MIN:
                        mdest = os.path.join(FETCHED, f"{msha[:12]}-{safe[:-4] if safe.lower().endswith('.zip') else safe}__{re.sub(r'[^A-Za-z0-9_.-]', '_', info.filename.split('/')[-1])[:60]}")
                        with open(mdest, "wb") as f:
                            f.write(mdata)
                        saved.append(mdest)
            except Exception:
                pass
        return saved

    for c in fresh[:max_downloads]:
        data = fetch(c)
        if not data:
            continue
        if is_html(data):
            # forum login/redirect wall, not a payload — record as gated
            seen[c["_key"]] = "gated-html"
            gated.append(c.get("url") or c["source"])
            continue
        sha = hashlib.sha256(data).hexdigest()
        if sha in seen:
            continue
        seen[c["_key"]] = sha
        seen[sha] = True
        downloaded += 1
        r = classify_bytes(data, f"{c.get('path') or c.get('url','?')} ({c['source']})")
        r["sha256"] = sha
        results.append(r)
        persist(c.get("path") or c.get("url", "file").split("/")[-1], data, sha)
        if r["hit"]:
            hits.append(r)
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", (c.get("path") or "hit").split("/")[-1])[:80]
            with open(os.path.join(QUARANTINE, f"HIT-{sha[:12]}-{safe}"), "wb") as f:
                f.write(data)
        elif downloaded <= 10 and len(data) <= 2 * 1024 * 1024:
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", (c.get("path") or "cand").split("/")[-1])[:80]
            with open(os.path.join(QUARANTINE, safe), "wb") as f:
                f.write(data)
    save_seen(seen)
    return results, hits, downloaded, len(fresh), gated


def write_report(results, hits, downloaded, fresh, allow_net, gated=()):
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [f"\n## Run {ts}  ({'full-net' if allow_net else 'github-only'})\n",
             f"- fresh candidates: {fresh}, downloaded+classified: {downloaded}",
             f"- **HITS (plaintext GENERATE engine): {len(hits)}**\n"]
    if gated:
        lines.append(f"- login-gated (HTML wall, no file): {len(gated)}")
        for g in gated[:15]:
            lines.append(f"  - GATED: {g[:120]}")
    for r in results[:40]:
        lines.append(f"- `{r['class']}` — {r['name'][:110]} — {r['detail'][:120]}")
    if hits:
        lines.append("\n**>>> HIT — run ec_generate_emu.py on the quarantined file <<<**")
    with open(REPORT, "a") as f:
        f.write("\n".join(lines) + "\n")
    if hits:
        with open(os.path.join(HERE, "HIT-ALERT.md"), "w") as f:
            f.write(f"# HIT — {len(hits)} plaintext GENERATE-engine candidate(s) found\n"
                    f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}\n\n")
            for h in hits:
                f.write(f"- {h['name']} sha256={h['sha256']}\n  {h['detail']}\n")


if __name__ == "__main__":
    allow_net = "--allow-net" in sys.argv
    maxd = 40
    if "--max" in sys.argv:
        maxd = int(sys.argv[sys.argv.index("--max") + 1])
    res, hits, dl, fresh, gated = hunt(maxd, allow_net)
    write_report(res, hits, dl, fresh, allow_net, gated)
    print(f"candidates={fresh} downloaded={dl} hits={len(hits)} gated={len(gated)}")
    for h in hits:
        print("HIT:", h["name"], h["detail"])
