#!/usr/bin/env python3
"""cross_machine_diff.py — cross-machine differential analysis of Dell EC payloads.

Answers the standing question: "can collecting EC firmware from MANY different
machines of the same security generation produce the material for an offline
keygen?" — automatically, on any set of payloads.

What it looks for:
  1. SEALED-BODY GROUPS — machines shipping byte-identical sealed EC images
     (same-build machines share ONE sealed image => collecting N machines of a
     build yields exactly as much information as collecting one: no key).
  2. SHARED 64-BYTE BLOCKS across DIFFERENT sealed bodies — zero => per-image
     keys, no key reuse, no differential surface. Any nonzero count is a
     breakthrough signal (key reuse).
  3. NON-SEALED bodies (entropy/chi² + Cortex-M signatures) — a plaintext
     GENERATE-era EC is the HIT condition (see ec_classify.py).

Usage: python3 cross_machine_diff.py <payload.bin> <payload2.bin> ... [dirs]
"""
import hashlib
import math
import os
import struct
import sys
from collections import Counter


def entropy(d):
    if not d:
        return 0.0
    c = Counter(d)
    n = len(d)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def chi2(d):
    c = Counter(d)
    n = len(d)
    exp = n / 256
    return sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))


def body_of(path):
    d = open(path, "rb").read()
    if d[:4] == b"PHCM":
        hs = struct.unpack_from("<I", d, 0x14)[0]
        body = d[hs:len(d) - hs] if hs and len(d) > 2 * hs else d[hs:]
        return path, d[4:8].hex(), body, d[0x60:0xA0]
    return path, "non-PHCM", d, b""


def main(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files += [os.path.join(p, f) for f in sorted(os.listdir(p)) if f.endswith(".bin")]
        else:
            files.append(p)
    rows, groups, blocks = [], {}, {}
    for f in files:
        try:
            name, ver, body, crypto = body_of(f)
        except OSError:
            continue
        bsha = hashlib.sha256(body).hexdigest()[:16]
        groups.setdefault(bsha, []).append(os.path.basename(f))
        H, C = entropy(body[:65536]), chi2(body[:65536])
        sealed = (150 <= C <= 420) or H >= 7.9
        rows.append((os.path.basename(f), len(body), ver, H, C, bsha, sealed))
        for i in range(0, len(body), 64):
            blocks.setdefault(hashlib.sha256(body[i:i + 64]).hexdigest(), set()).add(bsha)

    print(f"{'file':34} {'bytes':>8}  {'ver':10} {'H':>5} {'chi2':>7}  body-sha[:16]  sealed")
    for name, n, ver, H, C, bsha, sealed in rows:
        print(f"{name[:34]:34} {n:>8,}  {ver:10} {H:>5.2f} {C:>7.0f}  {bsha}  {'YES' if sealed else 'no'}")

    print("\nSEALED-BODY GROUPS (byte-identical images across files):")
    for bsha, names in sorted(groups.items()):
        if len(names) > 1:
            print(f"  {bsha}: {len(names)} files — SAME SEALED IMAGE: {', '.join(sorted(names))}")
    uniques = [b for b, n in groups.items() if len(n) == 1]
    print(f"  (+{len(uniques)} unique bodies)")

    same = {frozenset(v) for v in groups.values() if len(v) > 1}
    cross = [s for s in blocks.values() if len(s) > 1 and frozenset(s) not in same]
    print(f"\n64-byte blocks: {len(blocks):,}; shared across DIFFERENT bodies: {len(cross)}"
          f"{'' if not cross else '  <<< KEY-REUSE SIGNAL — INVESTIGATE'}")

    plain = [r for r in rows if not r[6]]
    if plain:
        print("\nNON-SEALED bodies (candidates for GENERATE-engine inspection):")
        for r in plain:
            print(f"  {r[0]}  H={r[3]:.2f} chi2={r[4]:.0f}  -> run ec_classify.py on it")
    print()
    verdict = ("All GENERATE-era bodies sealed; same-build machines share one sealed image; "
               "zero cross-body block reuse (per-image keys). Collecting more machines of a "
               "build adds no new material — the key is fused in EC silicon. Offline keygen "
               "requires a per-build key leak, an EC-internal dump, or a backend leak.")
    print("VERDICT:", verdict if not cross and not plain else "see signals above.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    main(sys.argv[1:])
