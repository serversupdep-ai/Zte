#!/usr/bin/env python3
"""Latest-suffix Dell BIOS master-code dispatcher + clean-room reconstruction.

WHAT THIS ANSWERS (2026-10-27, from GitHub file sources; see FINAL_REPORT.md)
---------------------------------------------------------------------------
The newest suffix seen on GitHub is **9ABE** (Precision 5680, BIOS 1.29.0,
pwgen-for-bios issue #333, 2026-10-13; Latitude 5440/3450 in #324/#330).  It
has **no new offline formula**.  In a real Latitude 5440 BIOS 1.28.1 image
committed to `serversupdep-ai/Bin-file`, the machine's own password module
lists 9ABE only in the *EC-routed family table* and gives 8FC8 a NULL encoder
pointer; the last suffix with a host-side algorithm is **E7A8**.  So the
"latest-suffix algorithm" is:

    master(tag, suffix) = RENDER( EC_GENERATE(tag, family_byte) )

with RENDER = resp32[0:16] verbatim for 9ABE/CF1B/3FE2/1B58, and
ALPHABET[(resp32[i]+resp32[i+16]) % 72] for 8FC8.  EC_GENERATE itself lives in
the sealed embedded controller and is not reproducible offline from public
material.  E7A8 (and everything older) is a deterministic function of the
service tag and is reconstructed here from scratch.

This module is a clean, original Python implementation (stdlib only).  The
numeric tables below are *facts* recovered from public firmware/source and are
independently re-extracted from the committed PE in evidence/.  No upstream
GPL source file is copied or bundled.  For hardware you own or are authorized
to service.

CLI examples
------------
    python3 latest_suffix.py 847TJ34-9ABE
    python3 latest_suffix.py 7QJ4H42-E7A8
    python3 latest_suffix.py 1K6Y963-8FC8 --resp 4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435
    python3 latest_suffix.py 1K6Y963-8FC8 --hypothesis   # DISPROVEN guess, for comparison
    python3 latest_suffix.py --catalog
    python3 latest_suffix.py --json 847TJ34-9ABE
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"

MASK = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Factual constants (recovered tables, not invented)
# Sources: bacher09/pwgen-for-bios src/keygen/dell/encode.ts (md5magic2,
# rotationTable, encodeParams, loopParams, alphabets); independently confirmed
# byte-for-byte inside evidence/DellSecurityVaultSmm_Latitude5440_1.28.1.pe at
# .data file offsets 0x8130 / 0x8178 / 0x81b0.
# ---------------------------------------------------------------------------

# MD5 K-table with rows 8..15 permuted (the "E7A8" variant).
ROUND_TABLE: Tuple[int, ...] = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
)

ROTATIONS: Tuple[Tuple[int, ...], ...] = (
    (7, 12, 17, 22),
    (5, 9, 14, 20),
    (4, 11, 16, 23),
    (6, 10, 15, 21),
)

E7A8_ALPHABET = (
    "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"
)
EC_ALPHABET = (  # 8FC8 render alphabet; also the BF97 multiset, permuted
    "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"
)
assert len(E7A8_ALPHABET) == len(EC_ALPHABET) == 72
assert sorted(E7A8_ALPHABET) == sorted(EC_ALPHABET)

ENCODE_PARAMS: Tuple[int, ...] = (
    0x50501010, 0x0A010908, 0x00A08097, 0x60606161,
    0x60606161, 0x000A0008, 0x00100097, 0x50501010,
)
SECOND_TABLE_TAIL: Tuple[int, ...] = tuple(
    v ^ 0x6D2F93A5 for v in (0xA0008, 0xA08097, 0xA010908, 0x60606161)
)

# ---------------------------------------------------------------------------
# Suffix catalogue (classification, not a keygen claim)
# ---------------------------------------------------------------------------

LOCAL_SHA256 = "local-sha256"      # E7A8 family: computed here
LEGACY_MD5 = "legacy-md5"          # 595B..BF97: public MD5-family keygens
EC_VERBATIM = "ec-verbatim"        # 9ABE/CF1B/3FE2/1B58: EC response[0:16]
EC_ALPHABET_MAP = "ec-alphabet"    # 8FC8: EC response sum -> 72-char alphabet
UNCONFIRMED = "unconfirmed"        # display variants / state words, no algorithm

LEGACY_SUFFIXES = ("595B", "D35B", "2A7B", "A95B", "1D3B", "1F5A",
                   "1F66", "6FF1", "BF97")
EC_VERBATIM_SUFFIXES = ("9ABE", "CF1B", "3FE2", "1B58")
UNCONFIRMED_SUFFIXES = ("8FCA", "8FDC8", "AE60", "A6E0", "0001", "8FCE")

FAMILY_BYTE: Dict[str, int] = {
    "CF1B": 0x1B, "8FC8": 0xC8, "1B58": 0x58,
    "9ABE": 0xBE, "3FE2": 0xE2,
}


@dataclass(frozen=True)
class SuffixSpec:
    word: str
    mechanism: str
    generation: str
    confidence: str                 # proven | probable | assumed
    evidence: Tuple[str, ...]
    family_byte: Optional[int] = None
    note: str = ""


def _spec(word: str, mechanism: str, generation: str, confidence: str,
          evidence: Sequence[str], note: str = "") -> SuffixSpec:
    return SuffixSpec(word, mechanism, generation, confidence,
                      tuple(evidence), FAMILY_BYTE.get(word), note)


CATALOG: Dict[str, SuffixSpec] = {}

for _s in LEGACY_SUFFIXES:
    CATALOG[_s] = _spec(
        _s, LEGACY_MD5, "2005-2020 (pre-EC)", "proven",
        ("bacher09/pwgen-for-bios src/keygen/dell/encode.ts",
         "chromebreakerdev/DellBIOSTools DellBiosTools.pyw:1373",
         "dell-keygen/vectors.json (72/72 public vectors)"),
        "Deterministic tag->code MD5-family keygen; not reimplemented here "
        "(use dell-keygen/keygen.html).",
    )

CATALOG["E7A8"] = _spec(
    "E7A8", LOCAL_SHA256, "2018-2026 (last host-side algorithm)", "proven",
    ("bacher09/pwgen-for-bios src/keygen/dell/encode.ts:403-497",
     "serversupdep-ai/Bin-file tools/dell_e7a8_pure.py (20/20 vectors)",
     "evidence/firmware_5440_1281.json (params @0x8178 byte-identical)"),
    "Two candidates ('Unlock Code 1/2'). Valid for BIOS branches carrying "
    "the published parameters; late/rotated branches need that image's params.",
)

CATALOG["8FC8"] = _spec(
    "8FC8", EC_ALPHABET_MAP, "2019-2026 (EC era; newest host-side table word)",
    "proven",
    ("pwgen-for-bios issue 80 comment 5067918343 (encoder_ptr NULL @0x9760)",
     "evidence/firmware_5440_1281.json (descriptor params = NULL @0x8810)",
     "Zte bios-analysis/CF1B_FINDINGS.md section 11.3 (render map)"),
    "Only suffix word kept in the newest (Gen-C) vault descriptor tables; "
    "its encoder pointer is NULL. Master = EC response rendered through "
    "the 72-char alphabet.",
)

_new_evidence = (
    "evidence/firmware_5440_1281.json (EC family list @0x81f8: "
    "1B58 9ABE 3FE2 CF1B 8FC8 FFFF)",
    "pwgen-for-bios issue 80 comments 4976691066 / 5935232074 (MEC EC, "
    "32-byte response, first 16 bytes compared)",
    "Zte bios-analysis/CF1B_FINDINGS.md section 11.3 + "
    "solution_kit/src/dell_ec_keygen.py",
    "pwgen-for-bios issues #324/#330/#331/#333 (2026 field sightings)",
)
for _s in EC_VERBATIM_SUFFIXES:
    _extra = ("",)
    _gen = "2019-2026 (EC era)"
    if _s == "9ABE":
        _gen = "2024-2026 (newest displayed suffix on GitHub)"
    CATALOG[_s] = _spec(
        _s, EC_VERBATIM, _gen, "proven" if _s != "9ABE" else "probable",
        _new_evidence,
        "Master = resp32[0:16] verbatim; second candidate = resp32[16:32]. "
        + ("Newest GitHub sighting: Precision 5680 847TJ34-9ABE, BIOS 1.29.0 "
           "(issue #333, 2026-10-13)." if _s == "9ABE" else ""),
    )

for _s in UNCONFIRMED_SUFFIXES:
    CATALOG[_s] = _spec(
        _s, UNCONFIRMED, "2024-2026 (reported, unconfirmed)", "assumed",
        ("serversupdep-ai/Bin-file analysis/9ABE_PAIR_HUNT.md section 5",
         "serversupdep-ai/Bin-file analysis/REPORT.md section 6d",
         "Zte bios-analysis/CF1B_FINDINGS.md section 9 (8FCA sighting)"),
        "Reported in forums/commercial service lists; not present as a "
        "firmware suffix word in any GitHub-sourced image examined. 8FCE / "
        "8FDC8 are probably OCR variants; 0001 is a lockout state word.",
    )

LATEST_DISPLAYED_SUFFIX = "9ABE"
LATEST_HOST_ALGORITHM_SUFFIX = "E7A8"


# ---------------------------------------------------------------------------
# Clean-room E7A8-family engine
# ---------------------------------------------------------------------------

def _rotl(value: int, bits: int) -> int:
    value &= MASK
    return ((value << bits) | (value >> (32 - bits))) & MASK


def _f2(b: int, c: int, d: int) -> int:
    nd = (~d) & MASK
    return (((nd ^ c) & b) ^ nd) & MASK


def _f3(b: int, c: int, d: int) -> int:
    return ((((b ^ c) & d) ^ c)) & MASK


def _f4(b: int, c: int, d: int) -> int:
    return ((((~c & MASK) ^ b) ^ d)) & MASK


def _f5(b: int, c: int, d: int) -> int:
    return (((((~b & MASK) | (~d & MASK)) & MASK) ^ c)) & MASK


class MixingEngine:
    """The 64-round MD5-shaped mixer used by the last local Dell keygen.

    Written from the arithmetic specification (evidence/ + upstream tables),
    not copied from any upstream implementation.  Two parameter sets produce
    the two published unlock codes.
    """

    def __init__(self, block: Sequence[int], table: Sequence[int],
                 loops: Sequence[int], params: Sequence[int] = ENCODE_PARAMS):
        if len(block) != 16:
            raise ValueError("block must be 16 little-endian 32-bit words")
        if len(loops) != 4:
            raise ValueError("loops must be (outer1, outer2, inner, depth)")
        self.block = list(block)
        self.table = tuple(table)
        self.loops = tuple(loops)
        self.params = tuple(params)
        self.a = self.b = self.c = self.d = 0
        self.accum = [0, 0, 0, 0]

    def _shortcut(self, fn, j: int, table_base: int, rotation_row: int,
                  offsets: Sequence[int]) -> None:
        for i, delta in enumerate(offsets):
            word = self.block[(j + delta) & 7]
            combined = (self.table[table_base + i] + word) & MASK
            t = (self.a + fn(self.b, self.c, self.d) - combined) & MASK
            old_b = self.b
            self.a = self.d
            self.d = self.c
            self.c = old_b
            self.b = (old_b + _rotl(t, ROTATIONS[rotation_row][i])) & MASK

    def _four_rounds(self, j: int, table_base: int, row: int, fn,
                     offsets: Sequence[int]) -> None:
        self._shortcut(fn, j, table_base, row, offsets)

    def run(self) -> List[int]:
        p0, p1, inner, depth = self.loops
        ep = self.params

        for p in range(p0):
            self.a |= ep[0]
            self.b ^= ep[1]
            self.c |= (ep[2] - p) & MASK
            self.d ^= (ep[3] + p) & MASK
            for j in range(0, inner, 4):
                self._four_rounds(j, j + 32, 0, _f2, (0, 1, 2, 3))
            for j in range(0, inner, 4):
                self._four_rounds(j, j, 1, _f3, (1, -2, -1, 0))
            for j in range(depth, 3, -4):
                self._four_rounds(j, j + 16, 2, _f4, (-3, -4, -1, 2))
            for j in range(depth, 3, -4):
                self._four_rounds(j, j + 48, 3, _f5, (2, 3, 2, -3))
            self.accum = [(x + y) & MASK for x, y in
                          zip(self.accum, (self.a, self.b, self.c, self.d))]

        for p in range(p1):
            self.a |= ep[4]
            self.b ^= ep[5]
            self.c |= (ep[6] - p) & MASK
            self.d ^= (ep[7] + p) & MASK
            for j in range(depth, 3, -4):
                self._four_rounds(j, j + 16, 2, _f4, (-3, -4, -1, 2))
            for j in range(0, inner, 4):
                self._four_rounds(j, j + 32, 3, _f5, (2, 3, 2, -3))
            for j in range(depth, 0, -4):
                self._four_rounds(j, j, 0, _f2, (0, 1, 2, 3))
            for j in range(0, inner, 4):
                self._four_rounds(j, j + 48, 1, _f3, (1, -2, 3, 0))
            self.accum = [(x + y) & MASK for x, y in
                          zip(self.accum, (self.a, self.b, self.c, self.d))]

        return list(self.accum)


def _screen_to_words(tag: str, suffix: str) -> List[int]:
    """(service tag + 4-char suffix) -> 16 zero-padded LE 32-bit words."""
    raw = (tag + suffix).encode("ascii")
    words = []
    for i in range(16):
        chunk = raw[i * 4:i * 4 + 4]
        words.append(int.from_bytes(chunk.ljust(4, b"\x00"), "little"))
    return words


def _render_state(state: Sequence[int], alphabet: str = E7A8_ALPHABET) -> str:
    raw = b"".join(int(v).to_bytes(4, "little") for v in state)
    digest = hashlib.sha256(raw).digest()
    n = len(alphabet)
    return "".join(alphabet[(digest[i + 16] + digest[i]) % n] for i in range(16))


def e7a8_codes(tag: str, suffix: str = "E7A8") -> Tuple[str, str]:
    """Both E7A8-family unlock codes for a service tag.

    ``suffix`` is part of the hashed serial.  For the real E7A8 path it is
    "E7A8".  Passing any other suffix reproduces the *unverified*
    ``secaicandido/bioskey`` hypothesis (see hypothesis_codes()).
    """
    block = _screen_to_words(tag, suffix)
    first = MixingEngine(block, ROUND_TABLE, (17, 13, 12, 8)).run()
    second = MixingEngine(block, ROUND_TABLE + SECOND_TABLE_TAIL,
                          (17, 13, 12, 16)).run()
    return _render_state(first), _render_state(second)


def hypothesis_codes(tag: str, suffix: str) -> Tuple[str, str]:
    """The 'hash the displayed suffix with the E7A8 engine' guess.

    This is what secaicandido/bioskey@f544e1e does for 3FE2/8FC8/CF1B/9ABE/
    1B58 (src/dell/types.ts SHA256_DELL_TAGS -> src/dell/index.ts:194).  It is
    NOT a validated latest-suffix algorithm: it fails all four public 8FC8
    field pairs and contradicts the firmware's NULL 8FC8 encoder.  Kept only
    as an explicit, testable negative control.
    """
    return e7a8_codes(tag, suffix)


# ---------------------------------------------------------------------------
# EC-era render (the actual latest-suffix host-side algorithm)
# ---------------------------------------------------------------------------

def render_ec_response(resp32: bytes, suffix: str,
                       alphabet: str = EC_ALPHABET) -> Tuple[str, str]:
    """Map a 32-byte EC GENERATE response to (master, second candidate).

    * 9ABE / CF1B / 3FE2 / 1B58 -> resp[0:16] verbatim; resp[16:32] = code 2
    * 8FC8 -> alphabet[(resp[i] + resp[i+16]) % 72] (code 2 is identical
      because integer addition commutes -- an observed edge case)
    """
    if len(resp32) < 32:
        raise ValueError("EC GENERATE response must be at least 32 bytes")
    s = suffix.upper()
    if s == "8FC8":
        out = "".join(alphabet[(resp32[i] + resp32[i + 16]) % len(alphabet)]
                      for i in range(16))
        # second candidate intentionally equal (parity with the in-repo kit)
        return out, out
    if s in EC_VERBATIM_SUFFIXES:
        return (resp32[0:16].decode("latin1"),
                resp32[16:32].decode("latin1"))
    raise ValueError(f"{s} is not an EC-era suffix")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

SCREEN_CODE_RE = re.compile(r"^([0-9A-Z]{6,7})[-: ]?([0-9A-Z]{4,5})$")


def parse_screen_code(text: str) -> Tuple[str, str]:
    m = SCREEN_CODE_RE.match(text.strip().upper())
    if not m:
        raise ValueError("expected e.g. 847TJ34-9ABE or 7QJ4H42E7A8")
    return m.group(1), m.group(2)


def resolve(screen_code: str, resp_hex: Optional[str] = None,
            include_hypothesis: bool = False) -> dict:
    """Classify a lock-screen code and produce whatever can be computed.

    Returns a JSON-serializable dict.  ``candidates`` is empty when the only
    honest answer is 'ask the machine's EC' (or Dell support / SPI patch).
    """
    tag, suffix = parse_screen_code(screen_code)
    spec = CATALOG.get(suffix)
    result: dict = {
        "input": screen_code.strip().upper(),
        "tag": tag,
        "suffix": suffix,
        "as_of": "2026-10-27",
        "latest_displayed_suffix": LATEST_DISPLAYED_SUFFIX,
        "last_host_side_algorithm_suffix": LATEST_HOST_ALGORITHM_SUFFIX,
        "mechanism": spec.mechanism if spec else "unknown",
        "generation": spec.generation if spec else "unknown",
        "confidence": spec.confidence if spec else "assumed",
        "family_byte": f"0x{spec.family_byte:02X}" if spec and spec.family_byte else None,
        "evidence": list(spec.evidence) if spec else [],
        "candidates": [],
        "second_candidates": [],
        "needs": None,
        "notes": [spec.note] if spec and spec.note else [],
    }

    if spec is None:
        result["notes"].append(
            "Not in the firmware suffix tables examined. Check for OCR "
            "confusion (8FC8/8FCA/8FDC8) and confirm on the lock screen.")
        result["needs"] = "confirmed suffix + machine BIOS image"
        return result

    if spec.mechanism == LOCAL_SHA256:
        a, b = e7a8_codes(tag, "E7A8")
        result["candidates"] = [a]
        result["second_candidates"] = [b]
        result["notes"].append(
            "Enter code 1; if rejected, enter code 2 (Ctrl+Enter on most "
            "models). Valid only for BIOS branches carrying the published "
            "E7A8 parameter block.")
        return result

    if spec.mechanism == LEGACY_MD5:
        result["needs"] = "legacy MD5-family keygen (dell-keygen/keygen.html)"
        result["notes"].append(
            "This reconstruction intentionally implements only the last "
            "local generation; legacy suffixes are already 72/72-validated "
            "in dell-keygen/.")
        return result

    if spec.mechanism in (EC_VERBATIM, EC_ALPHABET_MAP):
        result["needs"] = {
            "what": "32-byte EC GENERATE response from this exact machine",
            "wire": "session {21 00 03 06}; send tag (7B); send family LSB "
                    f"({result['family_byte']}); recv 32B; recv status",
            "ports": "0x910 / 0x911 (bare metal, root)",
            "reference_tool": "bios-analysis/solution_kit/src/dell_ec_keygen.py "
                              "--render / --keygen, or dell_cf1b_master.c",
            "alternatives": ["Dell support with proof of ownership",
                             "SPI dump patch (dell_unlock_image.py)"],
        }
        result["notes"].append(
            "No offline tag->password function exists for this suffix in "
            "public material: the newest firmware gives 8FC8 a NULL encoder "
            "and lists 9ABE only in the EC-routed family table.")
        if resp_hex:
            try:
                resp = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", resp_hex))
                a, b = render_ec_response(resp, suffix)
                result["candidates"] = [a]
                result["second_candidates"] = [b]
                result["needs"] = None
            except ValueError as exc:
                result["notes"].append(f"bad --resp: {exc}")
        if include_hypothesis:
            h1, h2 = hypothesis_codes(tag, suffix)
            result["hypothesis"] = {
                "name": "suffix-in-serial E7A8 (secaicandido/bioskey)",
                "status": "DISPROVEN for 8FC8 against 4 public field pairs; "
                          "unsupported for 9ABE (zero public pairs)",
                "candidates": [h1, h2],
            }
        return result

    result["needs"] = "a firmware image from that exact machine + confirmation"
    result["notes"].append(
        "Unconfirmed display word. No GitHub-sourced firmware table contains "
        "it; treat as an EC-era variant until proven otherwise.")
    if include_hypothesis and len(suffix) == 4:
        h1, h2 = hypothesis_codes(tag, suffix)
        result["hypothesis"] = {
            "name": "suffix-in-serial E7A8 (unverified)",
            "status": "speculative; not evidence-backed",
            "candidates": [h1, h2],
        }
    return result


def catalog_rows() -> List[dict]:
    rows = []
    for word, spec in CATALOG.items():
        rows.append({
            "suffix": word, "mechanism": spec.mechanism,
            "generation": spec.generation, "confidence": spec.confidence,
            "family_byte": f"0x{spec.family_byte:02X}" if spec.family_byte else None,
        })
    return rows


def _pretty(result: dict) -> str:
    lines = [
        f"Input       {result['input']}",
        f"Suffix      {result['suffix']}  ({result['generation']})",
        f"Mechanism   {result['mechanism']}  [confidence: {result['confidence']}]",
        f"Latest      displayed suffix {result['latest_displayed_suffix']}; "
        f"last host-side algorithm {result['last_host_side_algorithm_suffix']}",
    ]
    if result["family_byte"]:
        lines.append(f"EC family   {result['family_byte']}")
    if result["candidates"]:
        lines.append(f"MASTER      {result['candidates'][0]}")
    if result["second_candidates"]:
        lines.append(f"code 2      {result['second_candidates'][0]}")
    if result["needs"]:
        n = result["needs"]
        if isinstance(n, dict):
            lines.append(f"NEEDS       {n['what']}")
            lines.append(f"            {n['wire']}")
            lines.append(f"            tool: {n['reference_tool']}")
        else:
            lines.append(f"NEEDS       {n}")
    if "hypothesis" in result:
        h = result["hypothesis"]
        lines.append(f"HYPOTHESIS  {h['name']} -> {', '.join(h['candidates'])}")
        lines.append(f"            {h['status']}")
    for note in result["notes"]:
        lines.append(f"NOTE        {note}")
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("screen_code", nargs="?", help="e.g. 847TJ34-9ABE")
    ap.add_argument("--resp", help="32-byte EC GENERATE response as hex")
    ap.add_argument("--hypothesis", action="store_true",
                    help="also show the DISPROVEN suffix-in-serial guess")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--catalog", action="store_true", help="print suffix catalogue")
    args = ap.parse_args(argv)

    if args.catalog:
        print(json.dumps(catalog_rows(), indent=2))
        return 0
    if not args.screen_code:
        ap.print_help()
        return 2
    try:
        result = resolve(args.screen_code, args.resp, args.hypothesis)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_pretty(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
