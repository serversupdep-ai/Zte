#!/usr/bin/env python3
"""tag_vault_inventory.py — corpus-wide (service tag, SIVB vault) pair audit.

§11.20.6 logged the tag-derived-vault-key door as untestable ("no pair in the
corpus").  This tool re-audits that conclusion systematically across EVERY
full-chip dump held: reports SIVB vault locations plus every plausible Dell
service-tag candidate (keyword-adjacent ASCII, Dell variable-store markers,
7-char tags in cleartext NVRAM regions).

If any dump yields BOTH a readable tag and a vault, the §11.20.6 KDF matrix
becomes runnable (key = f(tag); test ECB/CBC/CTR against vault first 64B).

Usage: python3 tag_vault_inventory.py [--min-mb 4] [roots...]
"""
import os
import re
import struct
import sys

DEFAULT_ROOTS = [
    "bios-analysis/collected",
    ".",
]
MIN_SIZE_DEFAULT = 4 * 1024 * 1024

TAG_RE = re.compile(rb"\b([A-Z0-9]{7})\b")
KEYWORDS = [
    b"SVCTAG", b"svctag", b"SvcTag", b"ServiceTag", b"SERVICETAG",
    b"service tag", b"Service Tag", b"SERIAL", b"serial", b"AssetTag",
    b"asset tag", b"SYSTAG", b"SystemTag",
]
MFS_MAGIC = b"\x87\x78\x55\xaa"
MAGIC = b"SIVB"


def scan_tags(d):
    """Keyword-adjacent + bare 7-char tag candidates with context."""
    hits = []
    seen = set()
    for kw in KEYWORDS:
        start = 0
        while True:
            i = d.find(kw, start)
            if i < 0:
                break
            start = i + 1
            lo, hi = max(0, i - 4), min(len(d), i + len(kw) + 128)
            ctx = d[lo:hi]
            for m in TAG_RE.finditer(ctx):
                off = lo + m.start()
                cand = m.group(1)
                if cand in (b"SERVICE", b"SERIAL", b"ASSETTA", b"SYSTEMS"):
                    continue
                key = (cand, off)
                if key not in seen:
                    seen.add(key)
                    hits.append((off, cand, kw))
    # Dell variable-store pages (87 78 55 AA): collect 7-char ASCII tokens
    varstore = []
    start = 0
    while True:
        i = d.find(MFS_MAGIC, start)
        if i < 0:
            break
        start = i + 1
        page = d[i:i + 0x1000]
        printable = sum(1 for b in page if 0x20 <= b < 0x7f)
        if printable > 0x400:
            varstore.append(i)
    if varstore and len(hits) < 3:
        # last resort: tags in printable runs near varstore pages
        for vs in varstore[:40]:
            lo, hi = max(0, vs - 0x200), min(len(d), vs + 0x1200)
            for m in TAG_RE.finditer(d[lo:hi]):
                off = lo + m.start()
                key = (m.group(1), off)
                if key not in seen:
                    seen.add(key)
                    hits.append((off, m.group(1), b"<varstore>"))
    return hits, varstore


def scan_vaults(d):
    """SIVB magic at offset % 0x100 == 4 (verified: 0x3004, 0x103004, 0x22b004,
    0x33a004, 0x7cf004, 0x891004, 0x893004 all satisfy it)."""
    out = []
    start = 0
    while True:
        i = d.find(MAGIC, start)
        if i < 0:
            break
        start = i + 1
        if i >= 4 and (i % 0x100) == 4:
            out.append((i - 4, struct.unpack_from("<I", d, i - 4)[0]))
    return out


def main():
    roots = sys.argv[1:]
    min_mb = MIN_SIZE_DEFAULT
    if roots and roots[0].startswith("--min-mb"):
        min_mb = int(roots[0].split("=")[1]) * 1024 * 1024
        roots = roots[1:]
    if not roots:
        roots = DEFAULT_ROOTS
    files = []
    for root in roots:
        for dirpath, _dirnames, filenames in os.walk(root):
            if ".git" in dirpath:
                continue
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if sz >= min_mb:
                    files.append((p, sz))
    files.sort()
    print(f"scanning {len(files)} files >= {min_mb//(1024*1024)} MB\n")
    pairs = []
    for p, sz in files:
        try:
            d = open(p, "rb").read()
        except OSError:
            continue
        vaults = scan_vaults(d)
        if not vaults:
            continue
        tags, varstore = scan_tags(d)
        print(f"== {p}  ({sz/1024/1024:.1f} MB)")
        for off, hdr in vaults[:8]:
            mfs = d.find(MFS_MAGIC, off, off + 0x5000)
            print(f"   SIVB @ {off:#x} (hdr {hdr:#x})  MFS-at {hex(mfs) if mfs>=0 else '-'}")
        for off, cand, kw in tags[:12]:
            print(f"   tag? {cand.decode()} @ {off:#x} (near {kw.decode('latin1')})")
        if not tags:
            print("   tag candidates: none")
        print(f"   Dell varstore pages: {len(varstore)}")
        if tags:
            pairs.append((p, vaults, tags))
        print()
    print("=== SUMMARY: dumps with vault AND tag candidates ===")
    for p, vaults, tags in pairs:
        print(f"  {p}: {len(vaults)} vault(s), tags: "
              + ", ".join(t[1].decode() for t in tags[:5]))


if __name__ == "__main__":
    main()
