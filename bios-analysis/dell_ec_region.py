#!/usr/bin/env python3
"""
dell_ec_region.py — extract + map the 'EC region' found in Dell board dumps.

Layout discovered (2026-09-13, §11.8): Dell boards of the EC era carry an
EC-managed region in SPI with:
  - a boot descriptor:      {u32 ver?, u32 len1, u32 0x8040e000, u32 len2,
                             u32 SP, u32 entry}   (Nuvoton-class EC,
                             SP=0x2001xxxx, entry in EC flash VA space)
  - a vector table at +0    (identical byte-for-byte between a 2020 Latitude
                             5410 and an OptiPlex 3090 — one EC codebase)
  - ~0x8100 bytes of plaintext boot code (Thumb-2), handlers sparse
  - zero or more 0xf5c-byte sealed blocks (per-block crypto material
                             headers, entropy ~8) — the EC app, sealed
The GENERATE engine (CF1B/8FC8/...) is NOT in this region — it lives in the
EC chip's INTERNAL flash; this region is boot + staging.

Usage:
  python3 dell_ec_region.py <dump.bin> [region_offset_hex]
  (without offset: scans for the 00 e0 40 80 descriptor magic)
"""
import struct
import sys


def find_region(d):
    pat = bytes.fromhex("00e04080")
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0:
            return None
        # descriptor: magic at i-? — layout is {.., len, 0x8040e000, len, SP, entry}
        # layout: {u32 7, u32 len, 0x8040e000, u32 len2, SP, entry} then vector table
        try:
            sp, ent = struct.unpack_from("<II", d, i + 8)
        except struct.error:
            i += 1
            continue
        if 0x2000f000 <= sp < 0x20080000 and 0x100 <= ent < 0x40000 and ent % 2 == 0:
            return i + 0x10      # vector table starts right after the descriptor
        i += 1
    return None


def runs_of(d, base, span=0x40000):
    runs, i = [], base
    while i < min(base + span, len(d)):
        if d[i] != 0xFF:
            j = i
            while j < min(base + span, len(d)) and d[j] != 0xFF:
                j += 1
            runs.append((i - base, j - i))
            i = j
        else:
            i += 1
    merged = []
    for off, ln in runs:
        if merged and off - (merged[-1][0] + merged[-1][1]) < 16:
            merged[-1] = (merged[-1][0], off + ln - merged[-1][0])
        else:
            merged.append((off, ln))
    return merged


def main():
    path = sys.argv[1]
    d = open(path, "rb").read()
    if len(sys.argv) > 2:
        base = int(sys.argv[2], 16)
    else:
        base = find_region(d)
        if base is None:
            print("no EC-region descriptor found (00 e0 40 80 + SP/entry)")
            return 1
    sp, ent = struct.unpack_from("<II", d, base - 8)
    print(f"EC region (vector table) @ {base:#x}; SP={sp:#x} entry={ent:#x}")
    print(f"descriptor: {d[base-0x18:base].hex()}")
    print(f"vector[0..8]: {[hex(x) for x in struct.unpack_from('<8I', d, base)]}")
    r = runs_of(d, base)
    tot = sum(ln for _, ln in r)
    print(f"data blocks: {len(r)}, total {tot:#x} bytes")
    for off, ln in r:
        print(f"  VA {off:#08x}..{off+ln:#08x} ({ln:#7x})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
