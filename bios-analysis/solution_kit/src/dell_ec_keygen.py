#!/usr/bin/env python3
"""dell_ec_keygen.py — master-code pipeline for the NEW SUFFIXES (EC era only).

Families: 8FC8, CF1B, 9ABE, 3FE2, 1B58.
This tool contains NO legacy-suffix code (nothing derived from the
595B/D35B/2A7B/1D3B/1F66/6FF1/1F5A/BF97/E7A8 public keygen lineage).

Verified architecture (CF1B_FINDINGS.md §11.1-§11.7, emulation-validated):

    master(tag, suffix) = RENDER( EC_GENERATE(tag, family_byte) )

  EC_GENERATE  — inside the EC: session open {cmd 0x21, sub 3, type 6},
                 send service tag (7 bytes) + family LSB (1 byte),
                 receive 32-byte response + status byte (0 = OK).
  RENDER       — BIOS side, fn 0x8E18 (byte-verified against emulation):
                   CF1B / 3FE2 / 1B58 / 9ABE -> resp32[0:16] VERBATIM
                                                (resp32[16:32] = 2nd candidate)
                   8FC8                      -> alphabet0[(resp32[i]
                                                   + resp32[i+16]) % 72]

The EC_GENERATE transform exists in exactly three places: Dell's backend,
the AES-sealed EC update payloads, and the EC's INTERNAL flash. This tool
consumes the third — an EC-internal flash dump (RT809H direct-EC read,
"EC程序") of any 8FC8-family machine (2020-21 generation: OptiPlex
3080/3090/5080/7080, Latitude 3410/5410, Inspiron 5401/5501).

What it can do TODAY with any file you point it at:
  --triage <file>        classify the artifact (PHCM plaintext/sealed,
                         Cortex-M vector table, SPI EC-region, entropy) and
                         scan for GENERATE-engine markers, incl. the EC NVRAM
                         record store — record 0x15 IS the machine's enrolled
                         master password, stored as a plaintext string.

  --render <128-hex> --suffix CF1B
                         map a captured 32-byte GENERATE response to the
                         master code(s) — verified §11.3 vectors in --selftest.

  --selftest             run the emulation-evidence vectors
                         (CF1B -> "ABCDEFGHIJKLMNOP", 8FC8 -> "2rk9L1Gq53kZkFx["
                         for response "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345").

  --locate <ec-dump>     list mailbox-literal function candidates in a
                         plaintext Cortex-M image (wiring aid for --keygen).

  --keygen <ec-dump> --tag XXXXXXX --suffix CF1B [--handler 0xADDR]
                         drive the dump's GENERATE handler under unicorn
                         emulation and print the master. Optional dependency:
                         unicorn (auto-SKIPped with a clear message if absent).
"""

import math
import os
import re
import struct
import sys

# --------------------------------------------------------------------------
# 1. Family registry (new suffixes ONLY)
# --------------------------------------------------------------------------

FAMILY_BYTE = {           # §11.2 wire protocol (all distinct, verified)
    "CF1B": 0x1B,
    "8FC8": 0xC8,
    "1B58": 0x58,
    "9ABE": 0xBE,
    "3FE2": 0xE2,
}

# 8FC8 render alphabet (BIOS fn 0x8E18 index-0 table, §11.3, byte-verified)
ALPHABET_8FC8 = ("0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZr"
                 "kQFMxN[Z638myIL2r")

VERBATIM_FAMILIES = ("CF1B", "3FE2", "1B58", "9ABE")   # out = resp[0:16]

# EC NVRAM record ids of interest (FINDINGS_5X90_EC.md §1)
RECORD_NAMES = {
    0x0B: "service tag + family (11 B)",
    0x04: "ADMIN (setup) password string",
    0x05: "SYSTEM (boot) password string",
    0x15: "MASTER password string (factory-enrolled!)",
    0x03: "challenge/response value",
    0x21: "compare/lock state",
    0x2A: "flags/small data",
    0x31: "flags/small data",
    0x40: "flags/small data",
}

# --------------------------------------------------------------------------
# 2. RENDER — the verified response->code maps
# --------------------------------------------------------------------------

def render(resp32: bytes, suffix: str):
    """resp32: 32 bytes from the EC GENERATE session. Returns (master, second).
    second is meaningful for verbatim families (resp[16:32]) and for 8FC8
    (the same map over swapped halves — diagnostic only)."""
    suffix = suffix.upper()
    if len(resp32) != 32:
        raise ValueError("response must be exactly 32 bytes")
    if suffix == "8FC8":
        a = ALPHABET_8FC8
        out = "".join(a[(resp32[i] + resp32[i + 16]) % 72] for i in range(16))
        # code-2 candidate: swapped halves — identical to the master for
        # 8FC8 (addition commutes); kept for parity with the kit's
        # response_to_code2 semantics.
        return out, "".join(a[(resp32[i + 16] + resp32[i]) % 72]
                            for i in range(16))
    if suffix in VERBATIM_FAMILIES:
        first = resp32[0:16].decode("ascii", "replace")
        second = resp32[16:32].decode("ascii", "replace")
        return first, second
    raise ValueError(f"suffix {suffix} is not an EC-era family "
                     f"({', '.join(sorted(FAMILY_BYTE))})")


# --------------------------------------------------------------------------
# 3. Artifact triage — works on ANY file (stdlib only)
# --------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def find_all(data: bytes, pat: bytes, limit=64):
    out, i = [], data.find(pat)
    while i >= 0 and len(out) < limit:
        out.append(i)
        i = data.find(pat, i + 1)
    return out


def cortex_m_vector_table(d: bytes, off: int = 0):
    """True if a plausible Cortex-M vector table starts at off.
    Note: real Dell EC-region files start directly with the table and the
    reset entry can be EVEN (bit0=0), e.g. 3090 SP=0x20016F84/entry=0xA12C."""
    if off + 8 > len(d):
        return False
    sp, reset = struct.unpack_from("<II", d, off)
    return (0x20000000 <= sp < 0x20080000
            and 0x100 <= (reset & ~1) < 0x100000)


def phcm_info(d: bytes):
    """Locate PHCM containers and classify plaintext vs sealed."""
    out = []
    for i in find_all(d, b"PHCM", limit=16):
        if i + 0x20 > len(d):
            continue
        ver = d[i + 4:i + 8]
        try:
            body_off = struct.unpack_from("<I", d, i + 0x14)[0]
        except struct.error:
            body_off = 0
        body_off = body_off or 0x80
        body = d[i + body_off: i + body_off + 0x4000]
        if not body:
            continue
        h = entropy(body)
        kind = "PLAINTEXT (engine visible!)" if h < 7.2 else "SEALED (AES, key fused in EC)"
        out.append((i, ver.hex(), body_off, h, kind))
    return out


def nvram_records(d: bytes, start: int = 0, end: int = None):
    """Walk EC NVRAM record chains: {len, payload..., id, 0xAA}, align4 stride.
    Returns list of (offset, id, payload). Requires >=3 chained valid records
    to report a store (kills false positives)."""
    end = len(d) if end is None else end
    records = []
    p = (start + 3) & ~3
    while p < end - 4:
        L = d[p]
        if 4 <= L <= 40 and d[p + L - 1] == 0xAA:
            rid = d[p + L - 2]
            if rid < 0x80:
                # try to extend the chain
                chain, q = [], p
                while q < end - 4:
                    L2 = d[q]
                    if 4 <= L2 <= 40 and d[q + L2 - 1] == 0xAA and d[q + L2 - 2] < 0x80:
                        chain.append((q, d[q + L2 - 2], bytes(d[q + 1:q + L2 - 2])))
                        q += (L2 + 3) & ~3
                    else:
                        break
                if len(chain) >= 3:
                    records.extend(chain)
                    p = q
                    continue
        p += 4
    return records


def triage(path: str):
    d = open(path, "rb").read()
    name = os.path.basename(path)
    print(f"=== TRIAGE {name} ({len(d):,} bytes) ===")

    # PHCM containers
    phcms = phcm_info(d)
    for i, ver, body_off, h, kind in phcms:
        print(f"  PHCM @0x{i:X} ver={ver} body@+0x{body_off:X} "
              f"entropy={h:.2f} -> {kind}")

    # Cortex-M vector tables (offset 0 and after EC-region descriptors)
    for desc in find_all(d, bytes.fromhex("00e04080"), limit=8):
        try:
            sp, ent = struct.unpack_from("<II", d, desc + 8)
        except struct.error:
            continue
        if 0x2000f000 <= sp < 0x20080000 and 0x100 <= ent < 0x40000 and ent % 2 == 0:
            vt = desc + 0x10
            print(f"  EC-region boot descriptor @0x{desc:X} (SP=0x{sp:08X} "
                  f"entry=0x{ent:X}); vector table @0x{vt:X} "
                  f"{'VALID' if cortex_m_vector_table(d, vt) else 'invalid'}")
    if cortex_m_vector_table(d, 0):
        sp, rv = struct.unpack_from("<II", d, 0)
        h = entropy(d[:0x4000])
        kind = "boot/staging image, plaintext code" if h < 6.5 else "dense/sealed body"
        print(f"  Cortex-M vector table at offset 0 (SP=0x{sp:08X} "
              f"entry=0x{rv:08X}); first-4K entropy={h:.2f} ({kind}) — "
              "EC-region or EC-internal layout")

    # GENERATE-engine markers
    marks = []

    # a) the 8FC8/ascii72 alphabet (exact)
    for i in find_all(d, ALPHABET_8FC8.encode(), limit=8):
        marks.append((i, "8FC8 render alphabet (exact)"))

    # b) exactly-72-char mixed runs (the new-suffix render tables are 72)
    for m in re.finditer(rb"[0-9A-Za-z\[\]\.\+\-]{72}", d):
        if len(set(m.group())) >= 45:   # real alphabets are near-unique
            marks.append((m.start(), "render-table candidate (72 ch)"))
        if len(marks) > 48:
            break

    # c) family-byte table: all 5 family bytes within a 16-byte window
    #    (anchor on 0xE2 occurrences — C-speed find, few positions to test)
    fb = set(FAMILY_BYTE.values())
    n_fam = 0
    i = d.find(b"\xE2")
    while i >= 0 and n_fam < 8 and i < len(d) - 16:
        if fb <= set(d[i:i + 16]):
            marks.append((max(0, i - 8), "family-byte table {58,BE,E2,1B,C8} window"))
            n_fam += 1
        i = d.find(b"\xE2", i + 1)

    # d) mailbox window literals (0x400F0110..0x400F011B) — literal pools
    lit = 0
    for a in range(0x400F0110, 0x400F011C, 4):
        pat = struct.pack("<I", a)
        lit += len(find_all(d, pat, limit=32))
    if lit:
        marks.append((-1, f"mailbox window literals 0x400F0110-0x400F011B: {lit} refs"))

    # e) fixed type-4/5 enroll command (SMM-side marker; NOT expected in EC)
    if find_all(d, bytes.fromhex("8449624dccd17c4cbfe44d7f013ff25a"), limit=1):
        marks.append((-1, "fixed enroll command bytes (SMM/vault module material, "
                          "not EC-internal)"))

    # f) SHA-256 K-table (hash computation present?)
    if find_all(d, struct.pack("<I", 0x428A2F98), limit=1):
        marks.append((-1, "SHA-256 K-table constant present"))

    shown = 0
    for off, what in marks:
        if off < 0 or shown < 24:
            print(f"  marker @0x{off:X}: {what}" if off >= 0 else f"  marker: {what}")
            if off >= 0:
                shown += 1

    # NVRAM record store — the crown jewel
    recs = nvram_records(d)
    seen = {}
    for off, rid, payload in recs:
        seen.setdefault(rid, []).append((off, payload))
    if seen:
        print(f"  EC NVRAM record store: {len(recs)} records, ids "
              f"{sorted(seen)}")
        for rid in sorted(seen):
            label = RECORD_NAMES.get(rid, "unknown")
            for off, payload in seen[rid][:3]:
                show = payload[:40]
                try:
                    txt = show.rstrip(b"\x00").decode("ascii")
                    if all(32 <= c < 127 for c in show.rstrip(b"\x00")):
                        show = f"{txt!r} (plaintext string!)"
                    else:
                        show = show.hex()
                except UnicodeDecodeError:
                    show = show.hex()
                print(f"    id 0x{rid:02X} ({label}) @0x{off:X}: {show}")
    else:
        print("  no EC NVRAM record store found (expected for SPI/staging "
              "images — present only in EC-internal dumps)")

    # verdict
    verdict = []
    if any(h < 7.2 for _, _, _, h, _ in phcms):
        verdict.append("PLAINTEXT PHCM body — password engine readable")
    if any(h >= 7.2 for _, _, _, h, _ in phcms):
        verdict.append("sealed PHCM body(s) — engine not readable (expected "
                       "for update packages)")
    if cortex_m_vector_table(d, 0) or any(
            cortex_m_vector_table(d, i + 0x10)
            for i in find_all(d, bytes.fromhex("00e04080"), limit=8)):
        verdict.append("Cortex-M image present")
    if seen:
        verdict.append("NVRAM store present — EC-INTERNAL dump: enrolled "
                       "passwords may be directly readable above")
    print("  VERDICT: " + ("; ".join(verdict) if verdict else
                           "no EC structures recognized"))


# --------------------------------------------------------------------------
# 4. Mailbox-literal locator (wiring aid for plaintext Cortex-M images)
# --------------------------------------------------------------------------

def locate(path: str):
    """Find functions that reference the mailbox window — the dispatcher and
    its sub-handlers are where a GENERATE handler will live."""
    d = open(path, "rb").read()
    print(f"=== LOCATE mailbox refs in {os.path.basename(path)} ===")
    hits = []
    for a in range(0x400F0110, 0x400F011C, 4):
        for i in find_all(d, struct.pack("<I", a), limit=64):
            hits.append((i, a))
    hits.sort()
    for i, a in hits[:60]:
        # scan back up to 0x200 bytes for a push {..., lr} prologue
        fn = None
        for back in range(0, 0x200, 2):
            p = i - back
            if p >= 2 and 0xB500 <= struct.unpack_from("<H", d, p - 2)[0] <= 0xB5FF:
                fn = p - 2
                break
        print(f"  literal 0x{a:08X} @0x{i:X}"
              + (f"  <- fn ~0x{fn:X}" if fn else ""))
    if not hits:
        print("  none — not a mailbox-talking image (or sealed)")


# --------------------------------------------------------------------------
# 5. Emulation keygen (optional; requires unicorn)
# --------------------------------------------------------------------------

def keygen(path: str, tag: str, suffix: str, handler: int = None,
           base: int = 0x0):
    suffix = suffix.upper()
    if suffix not in FAMILY_BYTE:
        sys.exit(f"unsupported suffix {suffix}")
    try:
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
        from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                       UC_ARM_REG_R2, UC_ARM_REG_R3,
                                       UC_ARM_REG_SP, UC_ARM_REG_LR,
                                       UC_ARM_REG_PC)
    except ImportError:
        print("unicorn not installed — emulation keygen unavailable.\n"
              "  Install with:  pip install unicorn\n"
              "  (triage/render/locate modes work without it)")
        return 2

    d = open(path, "rb").read()
    if not cortex_m_vector_table(d, 0):
        print("WARNING: no Cortex-M vector table at offset 0 — if the image "
              "has a header, pass its body offset via --base")

    PAGE = 0x1000
    size = ((len(d) + PAGE - 1) // PAGE) * PAGE
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(base, max(size, 0x10000))
    uc.mem_write(base, d)
    sp0, reset = struct.unpack_from("<II", d, 0)
    uc.mem_map(0x20000000, 0x20000)                    # SRAM
    uc.mem_map(0x400F0000, 0x10000)                    # MMIO mailbox page
    uc.mem_write(0x400F0114, tag.encode() + bytes([FAMILY_BYTE[suffix]]))

    out_pkts = []

    def hook_write(uc_, access, addr, size_, value, _):
        if 0x400F0114 <= addr <= 0x400F011B:
            out_pkts.append((addr - 0x400F0114, value & 0xFF))

    uc.hook_add(35, hook_write, begin=0x400F0000, end=0x400F0200)  # UC_HOOK_MEM_WRITE

    if handler is None:
        print("No --handler given. Run --locate first, then pass the "
              "GENERATE handler address (the sub-3/type-6 case) with "
              "--handler 0xADDR.")
        return 1

    uc.reg_write(UC_ARM_REG_SP, sp0)
    uc.reg_write(UC_ARM_REG_LR, base | 1)
    for r, v in ((UC_ARM_REG_R0, 0), (UC_ARM_REG_R1, 0),
                 (UC_ARM_REG_R2, 0), (UC_ARM_REG_R3, 0)):
        uc.reg_write(r, v)
    try:
        uc.emu_start(handler | 1, base, count=5_000_000)
    except Exception as e:
        print(f"emulation stopped: {e}")

    resp = bytearray(32)
    for off, val in out_pkts:
        if off < 32:
            resp[off] = val
    print(f"raw outbound window bytes: {resp.hex()}")
    master, second = render(bytes(resp), suffix)
    print(f"\n  TAG {tag}  SUFFIX {suffix}")
    print(f"  MASTER CODE: {master}")
    if second:
        print(f"  second candidate (resp[16:32]): {second}")
    return 0


# --------------------------------------------------------------------------
# 6. Selftest — the §11.3 emulation-evidence vectors
# --------------------------------------------------------------------------

def selftest():
    ok = True
    # render vectors (captured from the emulated 3090 BIOS fn 0x8E18)
    resp = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    m, s = render(resp, "CF1B")
    if m != "ABCDEFGHIJKLMNOP" or s != "QRSTUVWXYZ012345":
        print(f"FAIL CF1B verbatim: {m!r} / {s!r}")
        ok = False
    m, _ = render(resp, "8FC8")
    if m != "2rk9L1Gq53kZkFx[":
        print(f"FAIL 8FC8 map: {m!r}")
        ok = False
    for f in ("3FE2", "1B58", "9ABE"):
        m, _ = render(resp, f)
        if m != "ABCDEFGHIJKLMNOP":
            print(f"FAIL {f} verbatim: {m!r}")
            ok = False
    if len(ALPHABET_8FC8) != 72:
        print(f"FAIL alphabet length {len(ALPHABET_8FC8)} != 72")
        ok = False
    if FAMILY_BYTE != {"CF1B": 0x1B, "8FC8": 0xC8, "1B58": 0x58,
                       "9ABE": 0xBE, "3FE2": 0xE2}:
        print("FAIL family byte table")
        ok = False
    print("selftest:", "ALL PASS" if ok else "FAILURES ABOVE")
    return 0 if ok else 1


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--selftest":
        return selftest()
    if args[0] == "--render":
        resp = bytes.fromhex(args[1])
        suffix = args[args.index("--suffix") + 1]
        m, s = render(resp, suffix)
        print(f"MASTER CODE: {m}")
        if s:
            print(f"second candidate (resp[16:32]): {s}")
        return 0
    if args[0] == "--triage":
        triage(args[1])
        return 0
    if args[0] == "--locate":
        locate(args[1])
        return 0
    if args[0] == "--keygen":
        path = args[1]
        tag = args[args.index("--tag") + 1]
        suffix = args[args.index("--suffix") + 1]
        handler = None
        if "--handler" in args:
            handler = int(args[args.index("--handler") + 1], 0)
        base = 0
        if "--base" in args:
            base = int(args[args.index("--base") + 1], 0)
        return keygen(path, tag, suffix, handler, base)
    print("unknown mode — see --help")
    return 1


if __name__ == "__main__":
    sys.exit(main())
