#!/usr/bin/env python3
"""
relay/fetch_files.py — generic fetch stage for the GitHub-Actions relay.

Reads relay/fetchlist.txt (lines 'PAGE|<url>|<tag>' or 'FILE|<url>|<name>'),
downloads pages/files that the sandbox cannot reach, extracts candidate
download links from pages (Google Drive / mediafire / direct .bin/.rar/.zip),
pulls them with gdown or curl, optionally unpacks archives (7z, password
candidates), and writes everything under:

    bios-analysis/collected/raw/<tag>/

plus a manifest.json with sha256s. Failures are logged, never fatal — the
relay commits whatever it got.

Used for the EC-chip-dump campaign (CF1B_FINDINGS.md §11.8): repair-forum
full-chip backups of Dell machines (Main + EC SPI chips) — the EC chip dump
contains the DECRYPTED EC firmware (the update-package payloads are sealed).
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTBASE = os.path.join(ROOT, "bios-analysis", "collected", "raw")
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
LINK_RX = re.compile(r'https?://[^\s"\'<>\\]+')
MAX_BYTES = 90 * 1024 * 1024
RAR_PW = ["indiafix", "vinafix", "badcaps", ""]


def log(msg):
    print(msg, flush=True)


def curl(url, dest=None, max_time="900"):
    cmd = ["curl", "-sSL", "--max-time", max_time, "-A", UA,
           "-H", "Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"]
    if dest:
        cmd += ["-o", dest, "-w", "%{http_code}", url]
        r = subprocess.run(cmd, capture_output=True, text=True)
        ok = r.stdout.strip() == "200" and os.path.exists(dest) and os.path.getsize(dest) > 0
        return ok, r.stdout.strip()
    cmd += [url]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0, r.stdout


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def save(tag, name, data=None, path=None):
    d = os.path.join(OUTBASE, tag)
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, name)
    if path:
        if os.path.getsize(path) > MAX_BYTES:
            log(f"    [skip] {name}: >{MAX_BYTES} bytes")
            return None
        subprocess.run(["cp", path, dest], check=True)
    else:
        with open(dest, "wb") as f:
            f.write(data)
    log(f"    [saved] {tag}/{name} ({os.path.getsize(dest)} bytes, sha256 {sha256(dest)[:16]}…)")
    return dest


def _drive_id(url):
    """Extract a Google-Drive file id from any link shape (incl. wayback-wrapped)."""
    u = re.sub(r"^https?://web\.archive\.org/web/\d+(?:id_)?/", "", url)
    m = re.search(r"/file/d/([A-Za-z0-9_-]{10,})", u)
    if m:
        return m.group(1)
    m = re.search(r"[?&]id=([A-Za-z0-9_-]{10,})", u)
    if m:
        return m.group(1)
    return None


def gdown(url, tag, name):
    d = os.path.join(OUTBASE, tag)
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, name)
    fid = _drive_id(url)
    dl_url = f"https://drive.google.com/uc?id={fid}" if fid else url
    r = subprocess.run([sys.executable, "-m", "gdown", "-O", dest, dl_url],
                       capture_output=True, text=True, timeout=1500)
    if r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0:
        if os.path.getsize(dest) > MAX_BYTES:
            os.remove(dest)
            log(f"    [skip] {name}: >{MAX_BYTES}")
            return None
        log(f"    [saved] {tag}/{name} via gdown ({os.path.getsize(dest)} bytes)")
        return dest
    log(f"    [gdown failed] {url}: {(r.stderr or r.stdout)[-300:]}")
    return None


def fetch_link(url, tag, idx):
    url = re.sub(r"^https?://web\.archive\.org/web/\d+(?:id_)?/", "", url)
    if "drive.google.com" in url or "docs.google.com" in url or "web.archive.org" in url and _drive_id(url):
        return gdown(url, tag, f"drive_{idx}.bin")
    if "mediafire.com" in url:
        ok, page = curl(url)
        if ok:
            m = re.search(r'href="(https?://download[^"]+)"', page)
            if m:
                dest = os.path.join(OUTBASE, tag, f"mediafire_{idx}.bin")
                ok2, _ = curl(m.group(1), dest)
                if ok2:
                    log(f"    [saved] {tag}/mediafire_{idx}.bin")
                    return dest
        log(f"    [mediafire failed] {url}")
        return None
    # direct file
    name = url.split("?")[0].rstrip("/").split("/")[-1] or f"file_{idx}.bin"
    if len(name) > 100 or "/" in name:
        name = f"file_{idx}.bin"
    d = os.path.join(OUTBASE, tag)
    os.makedirs(d, exist_ok=True)
    dest = os.path.join(d, name)
    ok, code = curl(url, dest)
    if ok:
        if os.path.getsize(dest) > MAX_BYTES:
            os.remove(dest)
            log(f"    [skip] {name}: >{MAX_BYTES}")
            return None
        log(f"    [saved] {tag}/{name} ({os.path.getsize(dest)} bytes)")
        return dest
    if os.path.exists(dest):
        os.remove(dest)
    log(f"    [fetch failed {code}] {url}")
    return None


def try_extract(tag):
    import glob
    d = os.path.join(OUTBASE, tag)
    # magic-based detection: gdown files are saved as drive_N.bin regardless of type
    archs = []
    for p in sorted(glob.glob(os.path.join(d, "*"))):
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as f:
            m = f.read(8)
        if m[:4] == b"Rar!":
            archs.append((p, ".rar"))
        elif m[:2] == b"PK":
            archs.append((p, ".zip"))
        elif m[:6] == b"7z\xbc\xaf\x27\x1c":
            archs.append((p, ".7z"))
    renamed = []
    for p, ext in archs:
        if not p.endswith(ext):
            np_ = p + ext
            os.rename(p, np_)
            renamed.append(np_)
            p = np_
        _extract_one(tag, p)
    for p in renamed:  # keep the original name too? no — extraction dir holds contents
        pass


def _extract_one(tag, arch):
    d = os.path.join(OUTBASE, tag)
    if os.path.exists(os.path.join(d, "extracted_" + os.path.basename(arch))):
        return
        ext = os.path.join(d, "extracted_" + os.path.basename(arch))
        done = False
        for pw in RAR_PW:
            for tool in (["7z", "x", "-y", f"-p{pw}", f"-o{ext}", arch],
                         ["unrar", "x", "-y", f"-p{pw}", arch, ext + os.sep]):
                r = subprocess.run(tool, capture_output=True, text=True, timeout=1200)
                if r.returncode == 0 and os.path.isdir(ext) and os.listdir(ext):
                    log(f"    [extracted] {os.path.basename(arch)} (pw={pw!r}, {'7z' if tool[0]=='7z' else 'unrar'}) -> {ext}")
                    done = True
                    break
            if done:
                break
        if not done:
            log(f"    [extract failed] {os.path.basename(arch)}: {(r.stderr or '')[-200:]}")


def process_page(url, tag):
    ok, page = curl(url)
    if not ok or len(page) < 200:
        # retry once (some hosts rate-limit the first hit)
        time.sleep(5)
        ok, page = curl(url)
    if not ok or len(page) < 200:
        log(f"    [page fetch failed] {url}")
        return
    log(f"    [page head] {page[:240]!r}")
    save(tag, "page.html", data=page.encode("utf-8", "replace"))
    links = []
    seen = set()
    for u in LINK_RX.findall(page):
        u = u.rstrip(').,];}').replace("&amp;", "&")
        if u in seen:
            continue
        if any(k in u for k in ("drive.google.com", "docs.google.com",
                                "mediafire.com", "mega.nz",
                                ".rar", ".zip", ".7z", ".bin", ".rom",
                                "archive.org/download")):
            if "google.com/search" in u or "blogger.com" in u or "gstatic" in u:
                continue
            seen.add(u)
            links.append(u)
    # also extract from JSON embedded in pages (reddit .json)
    for m in re.finditer(r'https?://(?:drive\\.google\\.com|docs\\.google\\.com|mega\\.nz)[^\\\\"]+', page):
        u = m.group(0).replace("\\/", "/").rstrip(').,];}')
        if u not in seen:
            seen.add(u); links.append(u)
    log(f"    [links] {len(links)} candidates")
    for i, u in enumerate(links):
        try:
            fetch_link(u, tag, i)
        except Exception as e:
            log(f"    [error] {u}: {e}")
        time.sleep(2)
    try_extract(tag)


def main():
    fetchlist = os.path.join(ROOT, "relay", "fetchlist.txt")
    if not os.path.exists(fetchlist):
        log("no fetchlist — nothing to do")
        return
    os.makedirs(OUTBASE, exist_ok=True)
    with open(fetchlist) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            kind = parts[0].upper()
            if kind == "PAGE" and len(parts) >= 3:
                url, tag = parts[1], parts[2]
                log(f"[PAGE] {url} -> raw/{tag}")
                try:
                    process_page(url, tag)
                except Exception as e:
                    log(f"    [page error] {e}")
            elif kind == "FILE" and len(parts) >= 3:
                url, name = parts[1], parts[2]
                tag = parts[3] if len(parts) > 3 else "misc"
                log(f"[FILE] {url} -> raw/{tag}/{name}")
                try:
                    fetch_link(url, tag, name)
                    try_extract(tag)
                except Exception as e:
                    log(f"    [file error] {e}")
    # extraction pass over every raw dir (idempotent; also catches files
    # committed by earlier runs)
    for tag in sorted(os.listdir(OUTBASE)):
        if os.path.isdir(os.path.join(OUTBASE, tag)):
            log(f"[EXTRACT-PASS] {tag}")
            try:
                try_extract(tag)
            except Exception as e:
                log(f"    [extract-pass error] {e}")

    # manifest
    for tag in os.listdir(OUTBASE):
        d = os.path.join(OUTBASE, tag)
        if not os.path.isdir(d):
            continue
        man = {"files": {}}
        for root, _dirs, files in os.walk(d):
            for fn in sorted(files):
                p = os.path.join(root, fn)
                rel = os.path.relpath(p, d)
                man["files"][rel] = {"bytes": os.path.getsize(p), "sha256": sha256(p)}
        with open(os.path.join(d, "manifest.json"), "w") as f:
            json.dump(man, f, indent=1)
    log("done")


if __name__ == "__main__":
    main()
