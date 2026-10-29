#!/usr/bin/env python3
"""Stdlib-only PE inspector for Dell password-vault suffix tables.

Re-extracts, from any DellSecurityVaultSmm-style PE, the three pieces of
evidence that decide which suffix has which algorithm:

  1. 24-byte local-keygen descriptor entries
     {u16 suffix, u16 pad, u32 pad, u64 params@+8, u64 alphabet@+16},
     terminated by 0xFFFF.  params == 0 means "no host-side derivation".
  2. 0xFFFF-terminated u16 EC-routed family lists (.data).
  3. 72-character output alphabets and the E7A8 parameter block.

This is independent of uefi_firmware/Unicorn: it only needs the extracted PE,
which we commit at evidence/DellSecurityVaultSmm_Latitude5440_1.28.1.pe.
Used by test_latest_suffix.py to prove the catalogue against real bytes.

    python3 vault_inspect.py [module.pe] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

DEFAULT_PE = (Path(__file__).resolve().parent / "evidence" /
              "DellSecurityVaultSmm_Latitude5440_1.28.1.pe")

KNOWN_WORDS = {
    0x595B, 0xD35B, 0x2A7B, 0xA95B, 0x1D3B, 0x1F5A, 0x1F66, 0x6FF1,
    0xBF97, 0xE7A8, 0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8, 0x0001,
    0xFFFF,
}
EC_FAMILIES = {0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8}


def pe_sections(data: bytes) -> List[Tuple[str, int, int, int, int]]:
    """[(name, virtual_address, virtual_size, raw_offset, raw_size)]."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image")
    opt_size = struct.unpack_from("<H", data, pe + 0x14)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    cursor = pe + 0x18 + opt_size
    out = []
    for _ in range(count):
        name = data[cursor:cursor + 8].rstrip(b"\x00").decode("latin1")
        vsize, va, rsize, ra = struct.unpack_from("<IIII", data, cursor + 8)
        out.append((name, va, vsize, ra, rsize))
        cursor += 40
    return out


def va_to_offset(sections: Sequence[Tuple[str, int, int, int, int]],
                 va: int) -> Optional[int]:
    for _name, base, vsize, ra, rsize in sections:
        if base <= va < base + vsize and va - base < rsize:
            return ra + (va - base)
    return None


def _data_slice(data: bytes, sections: Sequence[Tuple[str, int, int, int, int]]
                ) -> Tuple[int, bytes]:
    for name, _va, _vsize, ra, rsize in sections:
        if name == ".data":
            return ra, data[ra:ra + rsize]
    return 0, data


def _printable_run(data: bytes, off: Optional[int], length: int = 72) -> Optional[str]:
    if off is None or off < 0 or off + length > len(data):
        return None
    chunk = data[off:off + length]
    if sum(1 for c in chunk if 32 <= c < 127) < length - 2:
        return None
    return chunk.decode("latin1")


def descriptor_tables(data: bytes, sections) -> List[dict]:
    """Find 24-byte {suffix, params, alphabet} descriptor tables in .data."""
    base, region = _data_slice(data, sections)
    found: List[dict] = []
    for i in range(0, len(region) - 48, 8):
        word = struct.unpack_from("<H", region, i)[0]
        if word not in KNOWN_WORDS or word == 0xFFFF:
            continue
        params, alpha = struct.unpack_from("<QQ", region, i + 8)
        alpha_off = va_to_offset(sections, alpha)
        params_off = va_to_offset(sections, params) if params else 0
        alphabet = _printable_run(data, alpha_off)
        if alphabet is None or params_off is None:
            continue
        entries = []
        p = i
        for _ in range(8):
            w = struct.unpack_from("<H", region, p)[0]
            if w == 0xFFFF:
                entries.append({"suffix": "FFFF", "terminator": True})
                break
            if w not in KNOWN_WORDS or p + 24 > len(region):
                break
            pr, al = struct.unpack_from("<QQ", region, p + 8)
            if va_to_offset(sections, pr) is None and pr != 0:
                break
            a_str = _printable_run(data, va_to_offset(sections, al))
            entries.append({
                "suffix": f"{w:04X}",
                "params_va": hex(pr),
                "params_null": pr == 0,
                "alphabet": a_str,
                "entry_file_offset": hex(base + p),
            })
            p += 24
        if len(entries) >= 2:
            found.append({"table_file_offset": hex(base + i), "entries": entries})
    # keep one result per table (entries overlap when scanning each word)
    uniq: List[dict] = []
    seen = set()
    for t in found:
        key = tuple(e.get("entry_file_offset") for e in t["entries"])
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq


def family_lists(data: bytes, sections) -> List[dict]:
    """Find contiguous u16 runs of EC family words ending in 0xFFFF."""
    base, region = _data_slice(data, sections)
    out: List[dict] = []
    i = 0
    while i + 2 <= len(region):
        w = struct.unpack_from("<H", region, i)[0]
        if w not in EC_FAMILIES:
            i += 2
            continue
        words = []
        p = i
        while p + 2 <= len(region):
            x = struct.unpack_from("<H", region, p)[0]
            if x == 0xFFFF:
                words.append("FFFF")
                break
            if x not in EC_FAMILIES:
                break
            words.append(f"{x:04X}")
            p += 2
        if len(words) >= 4 and words[-1] == "FFFF":
            out.append({"file_offset": hex(base + i), "va": hex(
                next((va for n, va, _vs, ra, _rs in sections
                      if n == ".data"), 0) + i), "words": words})
            i = p + 2
        else:
            i += 2
    return out


def alphabets(data: bytes) -> List[dict]:
    """Locate the 72-char permutations used as render/output tables."""
    out = []
    start = 0
    while True:
        i = data.find(b"Q92G0drk", start)
        if i < 0:
            break
        start = i + 1
        s = _printable_run(data, i, 72)
        if s and sorted(s) == sorted(
                "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"):
            out.append({"file_offset": hex(i), "value": s, "length": len(s)})
    # also catch the 8FC8 / permuted variant directly
    start = 0
    while True:
        i = data.find(b"0Q2drGk9", start)
        if i < 0:
            break
        start = i + 1
        s = _printable_run(data, i, 72)
        if s:
            out.append({"file_offset": hex(i), "value": s, "length": len(s)})
    uniq, seen = [], set()
    for a in out:
        if a["file_offset"] not in seen:
            seen.add(a["file_offset"])
            uniq.append(a)
    return uniq


def params_at(data: bytes, sections, va: int) -> Optional[dict]:
    off = va_to_offset(sections, va)
    if off is None or off + 48 > len(data):
        return None
    vals = struct.unpack_from("<12I", data, off)
    return {
        "va": hex(va), "file_offset": hex(off),
        "encodeParams": [f"0x{x:08x}" for x in vals[:8]],
        "loopParams": list(vals[8:12]),
    }


def summarize(path: str | Path) -> dict:
    data = Path(path).read_bytes()
    sections = pe_sections(data)
    tables = descriptor_tables(data, sections)
    alpha = alphabets(data)
    params: List[dict] = []
    seen_params = set()
    for t in tables:
        for e in t["entries"]:
            if e.get("params_va") and not e.get("params_null"):
                p = params_at(data, sections, int(e["params_va"], 16))
                if p and p["file_offset"] not in seen_params:
                    seen_params.add(p["file_offset"])
                    params.append(p)
    return {
        "file": str(path),
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sections": [{"name": n, "va": hex(va), "vsize": vsize,
                      "raw_offset": hex(ra), "raw_size": rsize}
                     for n, va, vsize, ra, rsize in sections],
        "descriptor_tables": tables,
        "ec_family_lists": family_lists(data, sections),
        "alphabets": alpha,
        "params": params,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("module", nargs="?", default=str(DEFAULT_PE))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    info = summarize(args.module)
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"{info['file']}  {info['bytes']} bytes  sha256={info['sha256']}")
        for t in info["descriptor_tables"]:
            print(f"\nLOCAL KEYGEN DESCRIPTOR TABLE @ {t['table_file_offset']}")
            for e in t["entries"]:
                if e.get("terminator"):
                    print("    FFFF  <end>")
                else:
                    print(f"    {e['suffix']}  params={e['params_va']}"
                          f"{' (NULL)' if e['params_null'] else ''}"
                          f"  alphabet={e['alphabet']!r}")
        for f in info["ec_family_lists"]:
            print(f"\nEC-ROUTED FAMILY LIST @ {f['file_offset']}: "
                  + " ".join(f["words"]))
        for a in info["alphabets"]:
            print(f"\nALPHABET @ {a['file_offset']} ({a['length']}): {a['value']}")
        for p in info["params"]:
            print(f"\nPARAMS @ {p['file_offset']}: {p['encodeParams']} "
                  f"loops={p['loopParams']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
