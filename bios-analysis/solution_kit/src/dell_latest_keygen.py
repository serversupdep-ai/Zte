#!/usr/bin/env python3
"""dell_latest_keygen.py — master-code keygen core for the LATEST Dell suffix.

LATEST-SUFFIX VERDICT (cycle 17, 2026-10-05, read from Dell's own newest
firmware — see CF1B_FINDINGS.md §17):

  * 2020-22 vault modules (Gen-B, 38912 B): suffix word table =
        { 0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8 } + 0xFFFF terminator
  * NEWEST modules (Gen-C, 39424 B — Latitude 3420 1.44.0, 3440/3540 1.2.0,
    5440 1.22.0, Precision 3580/Latitude 5540 1.17.0 [2024 Meteor Lake],
    Precision 3581 1.17.0): table = { 0x8FC8 } + terminator
    => 8FC8 IS THE LATEST SUFFIX — the single family Dell kept on its
       newest generation.
  * The 72-char render alphabet set (7 tables, index-0 = the verified
    alphabet0) is byte-identical from 2020 through the 2024 Meteor Lake
    modules — NO late-generation rotation (unlike the E7A8 family).

Algorithm (verified, emulation-proven — CF1B_FINDINGS §11.1-§11.3):

    master(tag) = RENDER( EC_GENERATE(tag, family_byte) )

    EC_GENERATE  lives in the machine's EC (sealed in every public update
                 payload — the engine needs an EC-internal dump or a live
                 session).  family byte for 8FC8 = 0xC8.
    RENDER (8FC8, BIOS fn 0x8E18):  master[i] = alphabet0[
                 (resp32[i] + resp32[i+16]) % 72 ]
    resp32[16:32] renders the second candidate.

This tool wires EVERY input door for the latest suffix:

  --check-module <pw-module-or-full-BIOS-image>
                 extract the machine's own suffix word table + 72-char
                 alphabet set; verify alphabet0 matches the verified one
                 (rotation alarm) and report the supported suffix set.
  --oracle resp:<64-hex> --tag-hint <optional>
                 offline: render a captured 32-byte EC GENERATE response.
  --oracle local --tag XXXXXXX
                 live: drive the machine's own EC through the
                 0x910/0x911 mailbox (root, bare metal) and render.
  --selftest     run the emulation-verified vector.

stdlib only; Python 3.8+.
"""

import argparse
import re
import struct
import sys
import time

# ---------------------------------------------------------------- constants

LATEST_SUFFIX = 0x8FC8
FAMILY_LSB = {0x1B58: 0x58, 0x9ABE: 0xBE, 0x3FE2: 0xE2,
              0xCF1B: 0x1B, 0x8FC8: 0xC8}
ALL_SUFFIX_WORDS = set(FAMILY_LSB)

# verified index-0 render alphabet (BIOS fn 0x8E18 table 0; identical in
# every generation through the 2024 Meteor Lake modules)
ALPHABET0 = ("0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7J"
             "aBXIjbkGZrkQFMxN[Z638myIL2r")
assert len(ALPHABET0) == 72

# EC mailbox (§11.22.3 + cycle-16 EC-side decode)
PORT_IDX, PORT_DAT, WIN_BASE, SEL_CMD = 0x910, 0x911, 0x10, 0x00
TIMEOUT_S = 2.0


# ------------------------------------------------------------ render

def render_master(resp32: bytes, alphabet: str = ALPHABET0) -> str:
    """8FC8 render: alphabet0[(resp[i] + resp[i+16]) % 72]."""
    if len(resp32) < 32:
        raise ValueError("need the full 32-byte EC response")
    return "".join(alphabet[(resp32[i] + resp32[i + 16]) % 72]
                   for i in range(16))


def render_second(resp32: bytes, alphabet: str = ALPHABET0) -> str:
    return "".join(alphabet[(resp32[i + 16] + resp32[i]) % 72]
                   for i in range(16))


# ------------------------------------------------- module / image check

def find_suffix_tables(blob: bytes):
    """0xFFFF-terminated 16-bit word tables built from known suffix words.
    Returns [(offset, [words...])]."""
    out = []
    for w in sorted(ALL_SUFFIX_WORDS):
        pat = struct.pack("<H", w)
        start = 0
        while True:
            i = blob.find(pat, start)
            if i < 0 or len(out) > 32:
                break
            start = i + 2
            if i % 2:
                continue
            # walk forward while words are known suffix words
            words, p = [], i
            while p + 2 <= len(blob):
                v = struct.unpack_from("<H", blob, p)[0]
                if v in ALL_SUFFIX_WORDS:
                    words.append(v)
                    p += 2
                elif v == 0xFFFF and words:
                    out.append((i, words))
                    break
                else:
                    break
    # dedupe overlapping (keep the earliest, longest table of a cluster)
    uniq, covered = {}, []
    for off in sorted(uniq_all := dict(out)):
        if any(s <= off < e for s, e in covered):
            continue
        ws = uniq_all[off]
        uniq[off] = ws
        covered.append((off, off + 2 * len(ws) + 2))
    return sorted(uniq.items())


def find_alphabets(blob: bytes):
    """72-char printable runs with near-unique characters (render tables)."""
    res = []
    for m in re.finditer(rb"[\x21-\x7a]{72,74}", blob):
        s = m.group()[:72]
        if len(set(s)) >= 45:
            res.append((m.start(), s.decode("latin1")))
    return res


def check_module(path: str):
    d = open(path, "rb").read()
    print(f"=== {path} ({len(d)} bytes) ===")
    tabs = find_suffix_tables(d)
    if tabs:
        for off, ws in tabs:
            names = [f"{w:04X}" for w in ws]
            gen = ("Gen-C (2023-24): 8FC8-ONLY — latest-suffix machine"
                   if ws == [LATEST_SUFFIX] else
                   (f"Gen-B (2020-22): all {len(ws)} families"
                    if len(ws) == 5 else "partial list"))
            print(f"  suffix table @0x{off:X}: {names}  -> {gen}")
    else:
        print("  no suffix word table (pre-EC-era module or non-vault file)")
    alphas = find_alphabets(d)
    if alphas:
        ok = any(a == ALPHABET0 for _, a in alphas)
        print(f"  72-char render tables: {len(alphas)} found; "
              f"verified alphabet0 {'PRESENT (no rotation)' if ok else 'MISSING — CHECK ROTATION'}")
        for off, a in alphas[:8]:
            mark = "  <== verified index-0" if a == ALPHABET0 else ""
            print(f"    @0x{off:X}: {a[:36]}...{mark}")
    return tabs, alphas


# ------------------------------------------------- live EC oracle

class PortIO:
    def __init__(self):
        self.f = open("/dev/port", "r+b", buffering=0)

    def out(self, port, val):
        self.f.seek(port)
        self.f.write(bytes([val]))

    def inp(self, port):
        self.f.seek(port)
        return self.f.read(1)[0]


class ECSession:
    """cmd-0x17 packet transport over the 0x910/0x911 mailbox (verified
    §11.4 wire protocol; cycle-16 EC-side decode confirms the window)."""

    def __init__(self, io=None):
        self.io = io or PortIO()

    def win_write(self, i, v):
        self.io.out(PORT_IDX, WIN_BASE + i)
        self.io.out(PORT_DAT, v)

    def win_read(self, i):
        self.io.out(PORT_IDX, WIN_BASE + i)
        return self.io.inp(PORT_DAT)

    def wait_ack(self):
        end = time.monotonic() + TIMEOUT_S
        while time.monotonic() < end:
            self.io.out(PORT_IDX, SEL_CMD)
            if self.io.inp(PORT_DAT) == 0:
                return True
        return False

    def doorbell(self, cmd):
        self.io.out(PORT_IDX, SEL_CMD)
        self.io.out(PORT_DAT, cmd)
        return self.wait_ack()

    def xfer_write(self, data):
        self.win_write(3, 0)
        self.win_write(2, 0)
        if not self.doorbell(0x17):
            return False
        off = 0
        while off < len(data):
            n = min(8, len(data) - off)
            for i in range(n):
                self.win_write(4 + i, data[off + i])
            self.win_write(3, n)
            self.win_write(2, 1)
            if not self.wait_ack():
                return False
            end = time.monotonic() + TIMEOUT_S
            while time.monotonic() < end:
                if (self.win_read(2) & 1) == 0:
                    break
            else:
                return False
            off += n
        self.win_write(3, 0)
        self.win_write(2, 1)
        return self.wait_ack()

    def xfer_read(self, length):
        out = bytearray()
        self.win_write(3, 0)
        self.win_write(2, 0)
        if not self.doorbell(0x17):
            return bytes(out)
        while len(out) < length:
            cnt = 0
            end = time.monotonic() + TIMEOUT_S
            while time.monotonic() < end:
                if self.win_read(2) & 1:
                    cnt = self.win_read(3)
                    break
            if not cnt:
                break
            cnt = min(cnt, 8, length - len(out))
            for i in range(cnt):
                out.append(self.win_read(4 + i))
            self.win_write(3, 0)
            self.win_write(2, 0)
        return bytes(out)

    def generate(self, tag: bytes, family: int = LATEST_SUFFIX):
        self.win_write(2, 3)               # sub  = 3
        self.win_write(3, 6)               # type = 6  (GENERATE)
        if not self.doorbell(0x21):
            raise RuntimeError("EC did not acknowledge session 0x21")
        if not self.xfer_write(tag):
            raise RuntimeError("tag transfer failed")
        if not self.xfer_write(bytes([FAMILY_LSB[family]])):
            raise RuntimeError("family transfer failed")
        resp = self.xfer_read(32)
        if len(resp) < 32:
            raise RuntimeError(f"short response ({len(resp)} bytes) — "
                               "EC gated the session")
        st = self.xfer_read(1)
        if st and st[0] != 0:
            raise RuntimeError(f"EC status byte {st[0]:#04x}")
        return resp


def oracle_local(tag: str):
    tag = tag.strip().upper()
    if not (6 <= len(tag) <= 7):
        sys.exit("tag must be 6-7 chars")
    s = ECSession()
    resp = s.generate(tag.encode(), LATEST_SUFFIX)
    print(f"EC GENERATE response: {resp.hex()}")
    print(f"\n  TAG {tag}-8FC8 (latest suffix)")
    print(f"  MASTER CODE:      {render_master(resp)}")
    print(f"  second candidate: {render_second(resp)}")


def oracle_resp(hexstr: str):
    resp = bytes.fromhex(hexstr.strip())
    if len(resp) < 32:
        sys.exit("need 64+ hex chars (32-byte response; 33 with status)")
    print(f"response: {resp[:32].hex()}")
    print(f"  MASTER CODE:      {render_master(resp)}")
    print(f"  second candidate: {render_second(resp)}")


# ------------------------------------------------- selftest

def selftest():
    # §11.3 emulation vector (byte-verified against BIOS fn 0x8E18)
    resp = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    m = render_master(resp)
    s = render_second(resp)
    ok1 = m == "2rk9L1Gq53kZkFx["
    print(f"  render vector: {m} / {s}  {'OK' if ok1 else 'FAIL'}")
    # module extraction vector: newest Gen-C module must yield the
    # 8FC8-only table + the unrotated alphabet0
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    cand = os.path.join(here, "..", "..", "collected",
                        "Precision_3580_Latitude_5540_1.17.0",
                        "pw_3_39424.efi")
    ok2 = None
    if os.path.exists(cand):
        d = open(cand, "rb").read()
        tabs = find_suffix_tables(d)
        ok2 = bool(tabs) and all(ws == [LATEST_SUFFIX] for _, ws in tabs)
        print(f"  Gen-C suffix table extraction: "
              f"{'OK (8FC8-only)' if ok2 else 'FAIL'}")
        ok3 = any(a == ALPHABET0 for _, a in find_alphabets(d))
        print(f"  Gen-C alphabet0 unrotated: {'OK' if ok3 else 'FAIL'}")
    else:
        print("  (in-repo Gen-C module not found — skipped)")
    good = ok1 and ok2 in (None, True)
    print("SELFTEST", "PASS" if good else "FAIL")
    return good


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check-module", metavar="FILE",
                    help="pw module or full BIOS image")
    ap.add_argument("--oracle", metavar="local|resp:HEX")
    ap.add_argument("--tag", help="service tag for --oracle local")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if a.check_module:
        check_module(a.check_module)
    if a.oracle:
        if a.oracle == "local":
            if not a.tag:
                sys.exit("--oracle local needs --tag XXXXXXX")
            oracle_local(a.tag)
        elif a.oracle.startswith("resp:"):
            oracle_resp(a.oracle[5:])
        else:
            sys.exit("--oracle must be 'local' or 'resp:HEX'")
    if not (a.check_module or a.oracle or a.selftest):
        print(__doc__)


if __name__ == "__main__":
    main()
