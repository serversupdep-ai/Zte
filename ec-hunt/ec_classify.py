#!/usr/bin/env python3
"""ec_classify.py — classify a candidate file for the CF1B offline-keygen hunt.

Knows the artifact classes from the bios-analysis corpus (CF1B_FINDINGS
§11.7/§11.8) and answers the one question that matters:

    does this file carry the EC GENERATE engine in plaintext?

Classes:
  PHCM-F1.0-PLAINTEXT   old store-and-compare EC (5X90 class — NO GENERATE)
  PHCM-F1.1-SEALED      AES-sealed EC (per-image key fused in silicon) — dead end
  PHCM-F1.0-GENERATE    *** HIT *** plaintext EC with the type-6 GENERATE engine
  EC-REGION-STAGING     SPI-dump EC region (boot+tables plaintext, app sealed)
  CORTEX-M-PLAINTEXT    plaintext Thumb-2 image, markers inconclusive
  UNKNOWN

HIT criteria (weighted score, corpus-derived):
  - plaintext Cortex-M body (vector-table scorer + low entropy + prologues)
  - family-list marker: >=3 of {1B58, 9ABE, 3FE2, CF1B, 8FC8} as u16 LE
    within a 64-byte window (the EC GENERATE handler must know the family set)
  - salt 8dfc7b25 / SHA-256 K-table / 72-char alphabet / {C065AEAB} GUID
  - EC-internal images are the target ("EC程序", RT809H direct-EC reads)
"""
import math
import struct
import sys
from collections import Counter

FAMILIES = [0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8]
SALT = bytes.fromhex("8dfc7b25")            # universal EC-path salt (LE bytes 25 7b fc 8d)
SHA_K0 = bytes.fromhex("d76aa478")          # SHA-256 K-table first constant
GUID_C065 = bytes.fromhex("ABAE65C01CDD494DBD334578E106C700")  # {C065AEAB-...} LE-ish
ASCII72 = b"012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"


def entropy(d: bytes) -> float:
    if not d:
        return 0.0
    c = Counter(d)
    n = len(d)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def chi2_uniform(d: bytes) -> float:
    if not d:
        return 0.0
    c = Counter(d)
    n = len(d)
    exp = n / 256
    return sum((c.get(i, 0) - exp) ** 2 / exp for i in range(256))


def cortex_m_vector_score(d: bytes) -> float:
    """Plausibility that d starts (or contains) a Cortex-M vector table:
    initial SP in SRAM range and reset handler inside a flash-like range,
    plus Thumb code-shape density in the following bytes."""
    best = 0.0
    for off in range(0, min(len(d) - 8, 0x2000), 4):
        sp, rv = struct.unpack_from("<II", d, off)
        if 0x10000000 <= sp < 0x20080000 or 0x20000000 <= sp < 0x20080000:
            if 0x00000001 <= (rv & 0xFFFFFFFE) < 0x00100000 and rv & 1:
                window = d[off + 0x40: off + 0x1040]
                if window:
                    prologues = sum(1 for i in range(0, len(window) - 1, 2)
                                    if window[i] & 0xF0 == 0xB0 or window[i:i+2] == b"\x47\x70")
                    best = max(best, min(1.0, prologues / 200))
                    if best >= 0.5:
                        return best
    return best


def family_list_score(d: bytes) -> int:
    """Count family u16s co-located within a 64-byte window (>=3 = strong)."""
    fam_bytes = [struct.pack("<H", f) for f in FAMILIES]
    hits = 0
    for i in range(0, len(d) - 64, 2):
        window = d[i:i + 64]
        found = sum(1 for fb in fam_bytes if fb in window)
        if found >= 3:
            hits += 1
            if hits > 3:
                return found
    return 0


def markers(d: bytes) -> dict:
    return {
        "salt_8dfc7b25": d.count(SALT),
        "sha256_ktable": d.count(SHA_K0),
        "guid_c065aeab": d.count(GUID_C065),
        "alphabet72": d.count(ASCII72),
        "mailbox_910_911": d.count(struct.pack("<H", 0x910)) + d.count(struct.pack("<H", 0x911)),
        "family_list_windows": family_list_score(d),
    }


def classify_bytes(d: bytes, name: str = "?") -> dict:
    r = {"name": name, "size": len(d), "class": "UNKNOWN", "hit": False, "detail": ""}
    if len(d) < 256:
        r["detail"] = "too small"
        return r

    # --- PHCM container (Dell EC update/SPI-region format) ---
    phcm_offsets = [i for i in range(0, min(len(d), 0x200000), 1)
                    if d[i:i + 4] == b"PHCM"] if b"PHCM" in d[:0x200000] else []
    if d[:4] == b"PHCM":
        phcm_offsets = [0]
    if phcm_offsets:
        off = phcm_offsets[0]
        ver = d[off + 4:off + 8]
        hdr = struct.unpack_from("<I", d, off + 0x14)[0] if len(d) > off + 0x18 else 0
        fmt = "1.0-plaintext-era" if ver == b"\x00\x01\x00\x03" else (
              "1.1-sealed-era" if ver == b"\x01\x01\x84\x03" else f"unknown {ver.hex()}")
        body_off = off + (hdr or 0x80)
        end = len(d) - (hdr or 0x80) if (hdr and len(d) > 2 * (hdr or 0x80)) else len(d)
        if end <= body_off:
            end = len(d)
        body = d[body_off:end]
        win = body[:65536]
        H = entropy(win)
        C = chi2_uniform(win)
        aes_uniform = 150 <= C <= 420          # AES/CSPRNG: chi2 ~ 255 +/- 22
        vm = cortex_m_vector_score(body) if not aes_uniform else 0.0
        m = markers(d[off:off + 0x40000])
        if fmt.startswith("1.1") or aes_uniform or H >= 7.9:
            r["class"] = "PHCM-F1.1-SEALED" if fmt.startswith("1.1") else "PHCM-SEALED"
            r["detail"] = (f"format {fmt}, body entropy {H:.2f}, chi2 {C:.0f} — "
                           "AES-sealed, key fused in EC (dead end)")
        else:
            if m["family_list_windows"] >= 1 and (m["salt_8dfc7b25"] or m["sha256_ktable"]):
                r["class"] = "PHCM-F1.0-GENERATE"
                r["hit"] = True
                r["detail"] = f"PLAINTEXT EC + GENERATE markers {m}"
            else:
                r["class"] = "PHCM-F1.0-PLAINTEXT"
                r["detail"] = f"plaintext EC, markers {m} — old engine (5X90 class) unless markers say otherwise"
        r["markers"] = m
        return r

    # --- EC region staging descriptor inside a bigger SPI dump ---
    desc = struct.pack("<I", 0x8040E000)
    if desc in d[:0x1000000]:
        idx = d.find(desc)
        r["class"] = "EC-REGION-STAGING"
        r["detail"] = (f"Nuvoton-class EC boot descriptor at 0x{d.find(desc):x} — "
                       "SPI staging region: boot+tables plaintext, app sealed (engine EC-internal)")
        m = markers(d[max(0, idx - 0x100): idx + 0x9000])
        r["markers"] = m
        return r

    # --- bare firmware image ---
    H = entropy(d[:65536])
    vm = cortex_m_vector_score(d)
    m = markers(d)
    r["markers"] = m
    if vm >= 0.3 and H < 6.5:
        if m["family_list_windows"] >= 1 and (m["salt_8dfc7b25"] or m["sha256_ktable"] or m["alphabet72"]):
            r["class"] = "CORTEX-M-GENERATE-CANDIDATE"
            r["hit"] = True
            r["detail"] = f"plaintext Cortex-M + GENERATE markers {m}"
        else:
            r["class"] = "CORTEX-M-PLAINTEXT"
            r["detail"] = f"plaintext Cortex-M (score {vm:.2f}), markers {m}"
    elif H >= 7.5:
        r["detail"] = f"high entropy {H:.2f} — sealed/compressed/unknown binary"
    else:
        r["detail"] = f"entropy {H:.2f}, vector score {vm:.2f}, markers {m}"
    return r


def classify_file(path: str) -> dict:
    with open(path, "rb") as f:
        return classify_bytes(f.read(), path)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        r = classify_file(p)
        print(f"{r['class']:28} hit={r['hit']!s:5} {r['name']}  [{r['detail'][:120]}]")
