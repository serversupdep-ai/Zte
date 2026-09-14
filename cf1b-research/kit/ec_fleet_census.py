#!/usr/bin/env python3
"""ec_fleet_census.py -- fleet-wide census of Dell PHCM EC payloads.

Answers, reproducibly, three questions the 5X90 engine reversal raised:

 1. Which EC firmware payloads in the corpus are plaintext (engine visible)
    vs sealed (encrypted/compressed)?
 2. Is the OptiPlex 3090's own EC (all BIOS eras) inspectable?  (No: its
    bodies are AES-grade sealed -- chi-square uniformity ~ df, no zlib/LZMA.)
 3. Did the password-table machinery change at the 2.0.7 -> 2.27.0 era
    boundary in the BIOS pw modules?  (No: all family tables byte-identical;
    only a rebuild + removal of the "local" mode + enum 6->8.)

Usage:  python3 ec_fleet_census.py [--diff-pw4]
"""
import glob
import math
import re
import struct
import sys
from collections import Counter, defaultdict

ASCII72 = (b"012345679abcdefghijklmnopqrstuvwxyz0123456789"
           b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0")


def entropy(d):
    if not d:
        return 0.0
    c = Counter(d)
    n = len(d)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def chi2_uniform(d):
    """Pearson chi-square against uniform byte distribution (df=255).
    AES/CSPRNG output ~ 255 +/- 22; compressed data usually > 350."""
    c = Counter(d)
    n = len(d)
    exp = n / 256
    return sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))


def body_of(path):
    d = open(path, "rb").read()
    if d[:4] != b"PHCM":
        return None, None, None
    hs = struct.unpack_from("<I", d, 0x14)[0]
    body = d[hs:len(d) - hs] if hs and len(d) > 2 * hs else d[hs:]
    return d, hs, body


def census():
    rows = []
    for p in sorted(glob.glob("collected/*/ec_*.bin") +
                    glob.glob("ec_payloads/*.bin")):
        d, hs, body = body_of(p)
        if d is None:
            continue
        H = entropy(body[:32768])
        plain = H < 7.2
        engine = (ASCII72 in d) or (b"read_service_tag" in d)
        folder = p.split("/")[-2] if p.count("/") >= 2 else "."
        rows.append((folder, p.split("/")[-1], hs, H, plain, engine))
    return rows


def pw4_era_diff():
    """Diff the 2.0.7 vs 2.27.0 OptiPlex 3090 pw_4 (42K/43K) modules."""
    a = open("collected/OptiPlex_3090_2.0.7/pw_4_42496.efi", "rb").read()
    b = open("collected/OptiPlex_3090_2.27.0/pw_4_43008.efi", "rb").read()
    # .data: RAW offsets from the PE section tables
    da = a[0x8a00:0x8a00 + 0x102b]
    db = b[0x8c00:0x8c00 + 0x102b]

    tables = []
    for nm, d in (("2.0.7", da), ("2.27.0", db)):
        ss = [(m.start(), m.group().decode()) for m in re.finditer(rb"[\x20-\x7e]{40,}", d)]
        tables.append({s for _, s in ss})
        print(f"pw_4 {nm}: {len(ss)} long strings:")
        for o, s in ss:
            print(f"   +{o:#06x} {s[:76]}")
    print(f"\ntable sets identical: {tables[0] == tables[1]}")

    u16 = lambda d: [m.group().decode("utf-16-le")
                     for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", d)]
    print(f"UTF-16 2.0.7: {u16(da)}")
    print(f"UTF-16 2.27.0: {u16(db)}")
    # semantic field diffs
    for off, label in ((0x350, "field@+0x350"), (0x394, "field@+0x394")):
        print(f"{label}: 2.0.7={da[off:off+8].hex()}  2.27.0={db[off:off+8].hex()}")


def main():
    rows = census()
    pl = [r for r in rows if r[4]]
    enc = [r for r in rows if not r[4]]
    print(f"PHCM EC payloads: {len(rows)}   plaintext: {len(pl)}   sealed: {len(enc)}\n")
    print("PLAINTEXT (engine visible):")
    for folder, f, hs, H, _, engine in pl:
        print(f"  {folder}/{f}  H={H:.2f}  engine={'YES' if engine else 'no-markers'}")
    by = defaultdict(list)
    for folder, f, hs, H, _, _ in enc:
        by[folder].append(H)
    print("\nSEALED (encrypted/compressed), by model:")
    for folder, hs_list in sorted(by.items()):
        print(f"  {folder}  x{len(hs_list)}  H~{sum(hs_list)/len(hs_list):.2f}")
    # chi-square on the 3090 ECs specifically
    print("\n3090 EC body uniformity (chi-square, df=255):")
    for p in sorted(glob.glob("collected/OptiPlex_3090_*/ec_1_*.bin")):
        _, hs, body = body_of(p)
        print(f"  {p.split('/')[-2]}/{p.split('/')[-1]}: chi2={chi2_uniform(body[:32768]):.0f}"
              f"  (AES/CSPRNG ~255+/-22)")
    if "--diff-pw4" in sys.argv:
        print()
        pw4_era_diff()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
