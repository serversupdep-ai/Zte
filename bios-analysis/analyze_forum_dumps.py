#!/usr/bin/env python3
"""analyze_forum_dumps.py — real-machine dump analysis (Task 9, forum data).

Processes the real Dell machine dumps collected from repair forums
(bios-analysis/forum/opensources/) and commits the analysis as source data:

  per dump:
    - sha256, size, Intel flash-descriptor region map
    - Dell NVRAM record-store scan with the PROVEN §13.7 GUID encodings
      (record 6e978d37-... as stored + swapped, store b7a777d1-...),
      NVRAM snippets + 32-byte X_enrolled candidates around every hit
    - EC firmware (PHCM) payloads — raw carve + full FV/PFS walk — matched
      by sha256 against the bios-analysis/collected/ package corpus
    - password PE modules, likewise matched
  summary: bios-analysis/forum/analysis/summary.json + report.md

Usage:
  python3 analyze_forum_dumps.py                     # dumps/ only (sandbox)
  python3 analyze_forum_dumps.py --unpack-archives   # + archives/ (needs 7z)
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FORUM = os.path.join(HERE, "forum", "opensources")
OUTROOT = os.path.join(HERE, "forum", "analysis")

# PROVEN encodings (dell_keygen.py --findxenrolled, REPORT §13.7)
RECG = bytes.fromhex("378d976e2ec3b6438cebcc9aa215109e")   # record GUID as stored
RECG_R = bytes.fromhex("6e978d37c32e43b68cebcc9aa215109e")  # swapped fields
STORE = bytes.fromhex("d177a7b7b66e9e46ad1f1165eb92b3ff")   # store protocol GUID
GUID_PATTERNS = [("record_guid", RECG), ("record_guid_swapped", RECG_R),
                 ("store_protocol_guid", STORE)]

REGION_NAMES = ["descriptor", "bios", "me", "gbe", "platform_data",
                "dev_exp1", "dev_exp2", "dev_exp3"]
SKIP_EXT = (".pdf", ".brd", ".bdv", ".twv", ".jpg", ".png", ".txt",
            ".dll", ".exe", ".html", ".md")


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def parse_ifd(data):
    if len(data) < 0x20 or data[0x10:0x14] != bytes.fromhex("5aa5f00f"):
        return None
    import struct
    flmap0 = struct.unpack_from("<I", data, 0x14)[0]
    frba = ((flmap0 >> 16) & 0xFF) << 4
    regions = {}
    for i in range(8):                      # scan all 8 entries (NR is unreliable)
        base, limit = struct.unpack_from("<HH", data, frba + 4 * i)
        if base == 0xFFFF or limit == 0 or base == 0:
            continue
        lo, hi = base << 12, (limit << 12) | 0xFFF
        hi = min(hi, len(data) - 1)
        if lo < hi:
            regions[REGION_NAMES[i] if i < len(REGION_NAMES) else f"r{i}"] = [lo, hi]
    return regions or None


def guid_hits(data):
    hits = []
    for name, pat in GUID_PATTERNS:
        off = 0
        n = 0
        while n < 64:
            i = data.find(pat, off)
            if i < 0:
                break
            hits.append(dict(guid=name, offset=i))
            off = i + 1
            n += 1
    return hits


def xenrolled_candidates(window):
    """32-byte non-trivial windows in the record body (offsets +0x10..+0x40)."""
    out = []
    for o in range(0x10, min(0x40, len(window) - 32) + 1):
        c = window[o:o + 32]
        if c == b"\x00" * 32 or c == b"\xff" * 32:
            continue
        printable = sum(1 for b in c if 0x20 <= b < 0x7f)
        if printable >= 30:          # ASCII blob, not a hash
            continue
        nz = sum(1 for b in c if b)
        if nz < 12:                  # mostly empty
            continue
        out.append(dict(rel_offset=o, hex=c.hex()))
    return out


def build_index():
    idx = {}
    root = os.path.join(HERE, "collected")
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.startswith(("ec_", "pw_")):
                p = os.path.join(dirpath, fn)
                try:
                    idx[sha256(open(p, "rb").read())] = os.path.relpath(p, HERE)
                except OSError:
                    pass
    return idx


def trim_ec(seg):
    """Trim trailing flash padding: a run of >=16 0xFF bytes at the end."""
    i = len(seg)
    j = i
    while j >= 16 and seg[j - 16:j] == b"\xff" * 16:
        j -= 16
    return seg[:j]


def ec_match(seg, idx, prefix_idx):
    """Match an EC image against the package corpus.

    Returns (match_desc, exact_bool): exact sha match, else prefix match
    (machine image == package image + trailing flash metadata)."""
    s = sha256(seg)
    if s in idx:
        return idx[s], True
    key = s[:8] + sha256(seg[:0x1000])[:8]
    for path, blob in prefix_idx:
        if blob[:0x1000] == seg[:0x1000]:
            if blob[:len(seg)] == seg:
                return (f"{path} (machine image = package image prefix, "
                        f"pkg {len(blob):,} B)"), True
            return f"{path} (header match, body differs)", False
    return None, False


def harvest_dump(data, outdir, idx, prefix_idx):
    """EC payloads + pw modules; returns (ec_entries, pw_entries)."""
    ec, pw = [], []
    seen = set()
    # raw PHCM windows (EC firmware is stored raw in the SPI, A/B slots)
    off = 0
    while True:
        i = data.find(b"PHCM", off)
        if i < 0:
            break
        seg = trim_ec(data[i:i + 0x40000])
        if len(seg) > 0x8000 and sha256(seg) not in seen:
            seen.add(sha256(seg))
            ec.append((f"ec_slot_{i:07x}_{len(seg)}.bin", seg))
        off = i + 4
    # FV/PFS walk (shared with the catalog collector)
    try:
        sys.path.insert(0, HERE)
        from collect_from_catalog import harvest
        h_ec, h_pw = [], []
        harvest(data, h_ec, h_pw, set())
        for seg in h_ec:
            s = sha256(seg)
            if s in seen:
                continue
            seen.add(s)
            ec.append((f"ec_walk_{s[:8]}_{len(seg)}.bin", seg))
        for marker, seg in h_pw:
            s = sha256(seg)
            pw.append((f"pw_{s[:8]}_{len(seg)}.efi", seg))
    except Exception as ex:
        print(f"    ! harvest: {ex}")
    ec_out = []
    for fn, seg in ec:
        m, exact = ec_match(seg, idx, prefix_idx)
        if exact:
            # already in the committed package corpus — record, don't re-save
            ec_out.append(dict(file=fn, size=len(seg), sha256=sha256(seg),
                               matches_package=m))
            continue
        p = os.path.join(outdir, fn)
        if not os.path.exists(p):
            open(p, "wb").write(seg)
        ec_out.append(dict(file=fn, size=len(seg), sha256=sha256(seg),
                           matches_package=m, saved=True))
    pw_out = []
    seenp = set()
    for fn, seg in pw:
        s = sha256(seg)
        if s in seenp:
            continue
        seenp.add(s)
        entry = dict(file=fn, size=len(seg), sha256=s,
                     matches_package=idx.get(s))
        if idx.get(s) is None:      # new module — keep the binary
            p = os.path.join(outdir, fn)
            if not os.path.exists(p):
                open(p, "wb").write(seg)
            entry["saved"] = True
        pw_out.append(entry)
    return ec_out, pw_out


def analyze(path, src, idx, prefix_idx):
    data = open(path, "rb").read()
    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{src}__{os.path.basename(path)}")[:80]
    outdir = os.path.join(OUTROOT, tag)
    os.makedirs(outdir, exist_ok=True)
    info = dict(src=src, file=os.path.basename(path), size=len(data),
                sha256=sha256(data))
    info["regions"] = parse_ifd(data)
    hits = guid_hits(data)
    info["guid_hits"] = hits
    # NVRAM snippets + X_enrolled candidates around record-GUID hits
    info["nvram"] = []
    for h in hits:
        if not h["guid"].startswith("record"):
            continue
        lo = max(0, h["offset"] - 0x200)
        hi = min(len(data), h["offset"] + 0x200)
        fn = f"nvram_{h['guid']}_{h['offset']:07x}.bin"
        open(os.path.join(outdir, fn), "wb").write(data[lo:hi])
        window = data[h["offset"]:hi]
        info["nvram"].append(dict(offset=h["offset"], snippet=fn,
                                  xenrolled_candidates=xenrolled_candidates(window)))
    info["ec_payloads"], info["pw_modules"] = harvest_dump(data, outdir, idx, prefix_idx)
    open(os.path.join(outdir, "info.json"), "w").write(json.dumps(info, indent=1))
    print(f"  {tag}: size={len(data)} regions={bool(info['regions'])} "
          f"guids={len(hits)} ec={len(info['ec_payloads'])} pw={len(info['pw_modules'])}")
    return info


def unpack_archives(tmpdir):
    """Yield (path, src) for every bin ≥ 2MB inside the archives."""
    adir = os.path.join(FORUM, "archives")
    for fn in sorted(os.listdir(adir)):
        p = os.path.join(adir, fn)
        src = fn.rsplit(".", 1)[0]
        d = os.path.join(tmpdir, src)
        os.makedirs(d, exist_ok=True)
        ok = False
        for pw in ("indiafix", ""):
            cmd = ["7z", "x", "-y", f"-o{d}", f"-p{pw}", p]
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=900)
                if r.returncode == 0:
                    ok = True
                    break
            except Exception:
                pass
        if not ok:
            print(f"  ! 7z failed on {fn}")
            continue
        for root, _dirs, files in os.walk(d):
            for f in files:
                fp = os.path.join(root, f)
                if f.lower().endswith(SKIP_EXT):
                    continue
                if os.path.getsize(fp) >= 2 * 1024 * 1024:
                    yield fp, src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unpack-archives", action="store_true")
    ap.add_argument("--dumps-dir", default=os.path.join(FORUM, "dumps"))
    args = ap.parse_args()

    os.makedirs(OUTROOT, exist_ok=True)
    idx = build_index()
    prefix_idx = []
    for hs, path in idx.items():
        try:
            prefix_idx.append((path, open(os.path.join(HERE, path), "rb").read()))
        except OSError:
            pass
    print(f"corpus index: {len(idx)} package files, {len(prefix_idx)} blobs")

    results, seen_sha = [], set()

    def do(path, src):
        try:
            d = open(path, "rb").read(64)
        except OSError:
            return
        s = sha256(open(path, "rb").read())
        if s in seen_sha:
            return
        seen_sha.add(s)
        info = analyze(path, src, idx, prefix_idx)
        results.append(info)

    if os.path.isdir(args.dumps_dir):
        for fn in sorted(os.listdir(args.dumps_dir)):
            do(os.path.join(args.dumps_dir, fn), "dumps")

    if args.unpack_archives:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            for p, src in unpack_archives(td):
                do(p, src)

    # summary
    summary = dict(n_dumps=len(results), dumps=results)
    open(os.path.join(OUTROOT, "summary.json"), "w").write(
        json.dumps(summary, indent=1))

    # human report
    with open(os.path.join(OUTROOT, "report.md"), "w") as f:
        f.write("# Forum real-machine dump analysis (CF1B generation)\n\n")
        for r in results:
            f.write(f"## {r['src']} / {r['file']}\n\n"
                    f"- size {r['size']:,} B, sha256 `{r['sha256'][:16]}...`\n"
                    f"- flash descriptor: {'yes — ' + str(r['regions']) if r['regions'] else 'no'}\n"
                    f"- record/store GUID hits: {len(r['guid_hits'])}\n")
            for n in r["nvram"]:
                for c in n["xenrolled_candidates"]:
                    f.write(f"  - X_enrolled candidate @0x{n['offset']:X}+0x{c['rel_offset']:X}: "
                            f"`{c['hex']}`\n")
            if r["ec_payloads"]:
                f.write(f"- EC payloads: {len(r['ec_payloads'])}\n")
                for e in r["ec_payloads"]:
                    m = e["matches_package"] or "NO PACKAGE MATCH (new EC image!)"
                    f.write(f"  - {e['size']:,} B `{e['sha256'][:12]}` -> {m}\n")
            if r["pw_modules"]:
                f.write(f"- pw modules: {len(r['pw_modules'])}\n")
                for e in r["pw_modules"]:
                    m = e["matches_package"] or "NO PACKAGE MATCH (new module!)"
                    f.write(f"  - {e['size']:,} B `{e['sha256'][:12]}` -> {m}\n")
            f.write("\n")
    print(f"\nwrote {OUTROOT}/summary.json + report.md ({len(results)} dumps)")


if __name__ == "__main__":
    main()
