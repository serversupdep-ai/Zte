#!/usr/bin/env python3
"""collect_from_catalog.py — collect real Dell firmware data (EC + password modules).

Downloads the packages listed in relay/catalog.txt (unless --no-download),
extracts every PHCM (Embedded Controller) payload and every password-related
PE module (alphabet marker / OpenSSL SHA-256 build string), and writes them
to <out>/<tag>/ together with a manifest.json (sha256s, sizes, kinds).

Runs BOTH on a GitHub Actions runner (with network; see
.github/workflows/collect-dell-data.yml) and locally in the sandbox (against
already-downloaded files via --file). Results are committed to the repo —
this is the "collect real dump data from the internet, no machine needed"
pipeline (REPORT.md §13.8).

Usage:
  collect_from_catalog.py --catalog relay/catalog.txt --out bios-analysis/collected --download
  collect_from_catalog.py --file some_package.exe --out bios-analysis/collected
  collect_from_catalog.py --scan bios-analysis/collected   # re-scan existing dirs
"""
import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from uefi_firmware.pfs import PFSFile          # noqa: E402
from extract_pw_modules import find_dub        # noqa: E402

PW_MARKERS = (b"0Q2drGk99",                 # family-dispatch alphabet (all gens)
              b"SHA-256 part of OpenSSL")    # hash module build string


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def walk_objects(obj, sink):
    """Recursively collect every decompressed section/object content."""
    for d in getattr(obj, "objects", []) or []:
        content = b""
        for attr in ("_data", "data", "content", "_Content"):
            v = getattr(d, attr, None)
            if isinstance(v, (bytes, bytearray)) and v:
                content = bytes(v)
                break
        if content:
            sink.append(content)
        try:
            walk_objects(d, sink)
        except Exception:
            pass


def harvest(blob, ec_out, pw_out, seen, tmpdir="/tmp/collect_carve"):
    """Extract EC PHCM payloads and password PE modules from a package blob.

    Primary route: biosutilities DellPfsExtract (produces the Firmware/ tree
    with EC images etc.). Fallback: carve_streams + PFSFile/AutoParser
    recursion (mirrors analyze_dell_bios.py).
    """
    import tempfile
    import contextlib
    import io as _io
    # ---- primary: DellPfsExtract tree walk --------------------------------
    candidates = [blob]
    try:
        sys.path.insert(0, os.path.join(HERE, "tools", "BIOSUtilities"))
        from biosutilities.dell_pfs_extract import DellPfsExtract
        with tempfile.TemporaryDirectory() as td:
            ext = DellPfsExtract(input_object=bytearray(blob),
                                 extract_path=td, padding=8)
            if ext.check_format():
                with contextlib.redirect_stdout(_io.StringIO()):
                    ext.parse_format()
            for root, _dirs, files in os.walk(td):
                for fn in files:
                    p = os.path.join(root, fn)
                    try:
                        cur = open(p, "rb").read()
                    except OSError:
                        continue
                    if len(cur) >= 64:
                        candidates.append(cur)
    except Exception:
        pass
    # ---- fallback + descent: carve + PFS/FV parse queue --------------------
    import analyze_dell_bios as adb
    os.makedirs(tmpdir, exist_ok=True)
    try:
        carved = adb.carve_streams(blob, tmpdir)
        candidates += [b for _p, b in carved]
    except Exception:
        pass
    # capsule-wrapped PFS: add slices starting at every PFS.HDR. magic
    for off in range(0, min(len(blob), 0x100000)):
        if blob[off:off + 8] == b"PFS.HDR.":
            candidates.append(blob[off:])
            if sum(1 for c in candidates if c[:8] == b"PFS.HDR.") > 8:
                break
    visited = set()
    qi = 0
    while qi < len(candidates) and qi < 20000:
        cur = candidates[qi]
        qi += 1
        if not isinstance(cur, (bytes, bytearray)) or len(cur) < 64:
            continue
        cur = bytes(cur)
        h = sha256(cur[:0x10000])
        if h in visited:
            continue
        visited.add(h)
        _harvest_content(cur, ec_out, pw_out, seen)
        if cur[:8] == b"PFS.HDR.":
            try:
                pfs = PFSFile(cur)
                pfs.process()
                for s in getattr(pfs, "sections", []):
                    sd = getattr(s, "section_data", None)
                    if isinstance(sd, (bytes, bytearray)) and len(sd) >= 64:
                        candidates.append(bytes(sd))
            except Exception:
                pass
        try:
            from uefi_firmware import AutoParser
            f = AutoParser(cur).parse()
            if f:
                sink = []
                walk_objects(f, sink)
                for c in sink:
                    if isinstance(c, (bytes, bytearray)) and len(c) >= 64:
                        candidates.append(bytes(c))
        except Exception:
            pass


def _harvest_content(cur, ec_out, pw_out, seen):
    """Harvest PHCM blobs and password PE modules from one content buffer."""
    if cur[:4] == b"PHCM":
        full = sha256(cur)
        if full not in seen:
            seen.add(full)
            ec_out.append(cur)
        return
    for marker in PW_MARKERS:
        if marker in cur:
            try:
                from extract_pw_modules import carve_pe
                seg = carve_pe(cur, lambda *a: None)
            except Exception:
                seg = None
            if seg and 8000 < len(seg) <= 0x20000:   # pw modules are 9-128 KB
                full = sha256(seg)
                if full not in seen:
                    seen.add(full)
                    pw_out.append((marker, seg))
            break


def process_blob(blob, tag, outdir):
    """Extract EC/pw payloads from one package blob; return manifest entries."""
    os.makedirs(outdir, exist_ok=True)
    ec_out, pw_out, seen = [], [], set()
    harvest(blob, ec_out, pw_out, seen)
    entries = []
    for i, ec in enumerate(sorted(ec_out, key=len), 1):
        fn = os.path.join(outdir, f"ec_{i}_{len(ec)}.bin")
        open(fn, "wb").write(ec)
        entries.append({"file": fn, "kind": "ec", "size": len(ec), "sha256": sha256(ec)})
    for i, (marker, seg) in enumerate(sorted(pw_out, key=lambda t: len(t[1])), 1):
        fn = os.path.join(outdir, f"pw_{i}_{len(seg)}.efi")
        open(fn, "wb").write(seg)
        entries.append({"file": fn, "kind": "pw",
                        "marker": marker.decode("latin-1"),
                        "size": len(seg), "sha256": sha256(seg)})
    return entries


def load_pkg(path_or_data):
    if isinstance(path_or_data, (bytes, bytearray)):
        data = bytes(path_or_data)
    else:
        data = open(path_or_data, "rb").read()
    # DellUpdateBinary container -> PFS payload
    dub = find_dub(data)
    if dub:
        return dub
    if data[:8] == b"PFS.HDR.":
        return data
    return None




_LVFS_META_CACHE = {}


def lvfs_fetch(url):
    """LVFS device page (or direct cab URL) -> [(tag, blob), ...].

    Scrapes the newest 'Download Archive' .cab from the device page,
    downloads it and extracts the firmware payload(s) with 7z (runner).
    """
    import re as _re
    import io as _io
    import shutil as _shutil
    import subprocess as _subprocess
    import tempfile as _tempfile
    import urllib.request as _rq
    # The LVFS CDN serves the fwupd *client*; browser UAs from datacenter
    # IPs get 403/412 from its anti-bot. Try the official client UA first,
    # then full browser headers (with Referer, for hotlink-style checks).
    HEADERS = (
        {"User-Agent": "fwupd/1.9.27", "Accept": "*/*"},
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/124.0.0.0 Safari/537.36",
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "*/*;q=0.8",
         "Accept-Language": "en-US,en;q=0.9",
         "Referer": "https://fwupd.org/"},
    )

    def _get_with(u, hdr, binary=True, maxb=90 * 1024 * 1024):
        req = _rq.Request(u, headers=hdr)
        with _rq.urlopen(req, timeout=900) as r:
            data = r.read(maxb)
        return data if binary else data.decode("utf-8", "replace")

    def _get(u, binary=True, maxb=90 * 1024 * 1024):
        last = None
        for hdr in HEADERS:
            try:
                return _get_with(u, hdr, binary, maxb)
            except _rq.HTTPError as e:
                last = e
                if e.code == 404:
                    raise            # genuinely missing — no UA will fix it
            except Exception as e:
                last = e
        raise last

    def _load_metadata():
        """firmware.xml[.zst|.gz] -> [(ids, guids, [(ver, cabloc)...]), ...]
        (parsed once, cached across lvfs_fetch calls)."""
        import gzip
        import xml.etree.ElementTree as ET
        for mu in ("https://cdn.fwupd.org/downloads/firmware.xml.zst",
                   "https://cdn.fwupd.org/downloads/firmware.xml.gz"):
            if mu in _LVFS_META_CACHE:
                return _LVFS_META_CACHE[mu]
            try:
                raw = _get(mu, maxb=400 * 1024 * 1024)
            except Exception as e:
                print(f"    metadata {mu.rsplit('/', 1)[-1]}: {e}")
                continue
            if mu.endswith(".zst"):
                try:
                    p = _subprocess.run(["zstd", "-dc"], input=raw,
                                        capture_output=True, timeout=600)
                except (FileNotFoundError, _subprocess.TimeoutExpired):
                    print("    zstd unavailable — trying next metadata")
                    continue
                if p.returncode != 0:
                    print("    zstd failed — trying next metadata")
                    continue
                raw = p.stdout
            else:
                raw = gzip.decompress(raw)
            comps = []
            for _, el in ET.iterparse(_io.BytesIO(raw), events=("end",)):
                if el.tag.endswith("component"):
                    ids = {i.text.strip().lower() for i in el.iter()
                           if i.tag.endswith("id") and i.text}
                    guids = {g.text.strip().lower() for g in el.iter()
                             if g.tag.endswith("firmware") and g.text}
                    rels = []
                    for rel in el.iter():
                        if rel.tag.endswith("release"):
                            ver = rel.get("version", "")
                            loc = rel.find("{*}location")
                            if loc is not None and loc.text and \
                                    loc.text.strip().endswith(".cab"):
                                rels.append((ver, loc.text.strip()))
                    if rels:
                        comps.append((ids, guids, rels))
                    el.clear()
            _LVFS_META_CACHE[mu] = comps
            return comps
        return []

    def _cab_from_metadata(slug, guid):
        """Fallback when the device page 403s: pull the release list from
        the official fwupd remote metadata (firmware.xml[.zst|.gz]) and
        return the newest .cab URL for this device. The device-page slug is
        the fwupd component id (e.g. com.dell.uefic9284bf6.firmware); match
        it against <id>, and also accept the bare GUID against <provides>
        <firmware type="flashed"> entries."""
        comps = _load_metadata()
        want_slug, want_guid = slug.lower(), guid.lower()
        comp = []
        for ids, guids, rels in comps:
            if want_slug in ids or want_guid in guids:
                comp.extend(rels)
        if comp:
            comp.sort(key=lambda x: [int(p) if p.isdigit() else 0
                                     for p in x[0].split(".")])
            return comp[-1][1], comp[-1][0]
        return None, None

    model = version = None
    if "/lvfs/devices/" in url:
        slug = url.rsplit("/", 1)[-1]           # e.g. com.dell.uefic9284bf6.firmware
        guid = slug[:-len(".firmware")] if slug.endswith(".firmware") else slug
        try:
            html = _get(url, binary=False)
        except Exception as e:
            print(f"    device page: {e} — falling back to LVFS metadata")
            cab_url, ver = _cab_from_metadata(slug, guid)
            if not cab_url:
                raise
            # AppStream <location> is often a bare filename — join it with
            # the LVFS downloads base (prefer the CDN).
            if "://" not in cab_url:
                cab_url = "https://cdn.fwupd.org/downloads/" + cab_url
            url, version = cab_url, ver or "latest"
            model = guid
        else:
            t = _re.search(r"<title>LVFS:\s*([^<]+)</title>", html)
            v = _re.search(r"##\s*Version\s*([0-9][0-9A-Za-z.+-]*)", html)
            model = t.group(1).strip() if t else "Dell"
            version = v.group(1) if v else "latest"
            m = _re.search(
                r"https://fwupd\.org/downloads/[0-9a-f]{64}-[^\"'<>]+?\.cab",
                html)
            if not m:
                print(f"    no cab link on device page: {url}")
                return []
            url = m.group(0)
    print(f"    cab: {url.rsplit('/', 1)[-1]}")
    # try both hosts (cdn <-> www) x both header sets — the CDN anti-bot
    # is picky about UA from datacenter IPs (403/412)
    name = url.rsplit("/", 1)[-1]
    tries = [url]
    for h in ("https://cdn.fwupd.org/downloads/",
              "https://fwupd.org/downloads/"):
        if h + name not in tries:
            tries.append(h + name)
    data = None
    last = None
    for u in tries:
        for hdr in HEADERS:
            try:
                data = _get_with(u, hdr)
                break
            except Exception as e:
                last = e
        if data is not None:
            if u != url:
                print(f"    fetched via {u.split('/')[2]}")
            break
    if data is None:
        raise last
    if data[:4] != b"MSCF":
        name = url.rsplit("/", 1)[-1]
        tag = _re.sub(r"^[0-9a-f]{64}-", "", name)
        tag = _re.sub(r"[^A-Za-z0-9._-]+", "_", tag)
        return [(tag, data)]
    out = []
    with _tempfile.TemporaryDirectory() as td:
        cab = os.path.join(td, "fw.cab")
        open(cab, "wb").write(data)
        r = _subprocess.run(["7z", "x", "-y", f"-o{td}\fw", cab],
                            capture_output=True, timeout=900)
        if r.returncode != 0:
            print(f"    7z failed: {r.stderr.decode()[:200]}")
            return []
        for root, _dirs, files in os.walk(os.path.join(td, "fw")):
            for fn in files:
                fp = os.path.join(root, fn)
                if os.path.getsize(fp) < 1024 * 1024:
                    continue
                blob = open(fp, "rb").read()
                if model:
                    tag = f"{model}_{version}"
                else:
                    tag = _re.sub(r"[^A-Za-z0-9._-]+", "_", fn)
                tag = _re.sub(r"[^A-Za-z0-9._-]+", "_", tag)
                out.append((tag, blob))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--catalog", default=None)
    ap.add_argument("--out", default="bios-analysis/collected")
    ap.add_argument("--file", action="append", default=[],
                    help="process a local package file (repeatable)")
    ap.add_argument("--download", action="store_true",
                    help="download catalog URLs (runner mode)")
    ap.add_argument("--scan", default=None,
                    help="re-scan an existing collected/ dir for salts etc.")
    args = ap.parse_args()

    if args.scan:
        # summary mode: list everything already collected
        root = args.scan
        for tag in sorted(os.listdir(root)):
            d = os.path.join(root, tag)
            if not os.path.isdir(d):
                continue
            mf = os.path.join(d, "manifest.json")
            n = json.load(open(mf)) if os.path.exists(mf) else []
            ecs = [e for e in n if e["kind"] == "ec"]
            pws = [e for e in n if e["kind"] == "pw"]
            print(f"{tag}: {len(ecs)} EC payloads, {len(pws)} pw modules")
        return

    jobs = []
    if args.catalog:
        for line in open(args.catalog):
            line = line.split("#", 1)[0].strip()   # strip inline comments
            if not line:
                continue
            jobs.append(line)
    for f in args.file:
        jobs.append(f)

    for i, job in enumerate(jobs, 1):
        url = None
        path = job
        if "fwupd.org/lvfs/devices/" in job or job.endswith(".cab"):
            if not args.download:
                print(f"[{i}] skip (no --download): {job}")
                continue
            print(f"[{i}] LVFS {job}")
            try:
                for tag, blob in lvfs_fetch(job):
                    entries = process_blob(blob, tag,
                                           os.path.join(args.out, tag))
                    print(f"    {tag}: {len(entries)} payloads")
            except Exception as e:
                print(f"    LVFS FAILED: {e}")
            continue
        if job.startswith("http"):
            if not args.download:
                print(f"[{i}] skip (no --download): {job}")
                continue
            import urllib.request
            url = job
            tag = re.sub(r"[^A-Za-z0-9._-]+", "_", job.rsplit("/", 1)[-1])
            if tag.lower().endswith(".exe"):
                tag = tag[:-4]
            path = os.path.join("/tmp" if os.path.isdir("/tmp") else ".", tag + ".exe")
            print(f"[{i}] downloading {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            try:
                with urllib.request.urlopen(req, timeout=900) as r, open(path, "wb") as f:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            except Exception as e:
                print(f"    DOWNLOAD FAILED: {e}")
                continue
        tag = re.sub(r"[^A-Za-z0-9._-]+", "_",
                     os.path.splitext(os.path.basename(path))[0])
        outdir = os.path.join(args.out, tag)
        print(f"[{i}] processing {path} -> {outdir}")
        blob = load_pkg(path)
        if blob is None:
            print("    no Dell PFS container found, skipping")
            continue
        entries = process_blob(blob, tag, outdir)
        mf = os.path.join(outdir, "manifest.json")
        old = []
        if os.path.exists(mf):
            try:
                _j = json.load(open(mf))
                old = _j["entries"] if isinstance(_j, dict) else _j
            except Exception:
                old = []
        known = {e["sha256"] for e in old}
        merged = old + [e for e in entries if e["sha256"] not in known]
        json.dump({"url": url, "entries": merged}, open(mf, "w"), indent=1)
        print(f"    {len(entries)} new payloads "
              f"({sum(1 for e in entries if e['kind']=='ec')} EC, "
              f"{sum(1 for e in entries if e['kind']=='pw')} pw); "
              f"manifest total {len(merged)}")


if __name__ == "__main__":
    main()
