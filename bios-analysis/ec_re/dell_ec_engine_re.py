#!/usr/bin/env python3
"""dell_ec_engine_re.py — Dell EC firmware reverse-engineering workbench (cycle 16).

Built on never-used sources: morluto/REA (PE/artifact lanes; Ghidra lane blocked
by CDN egress in the sandbox), capstone + unicorn (PyPI), and the FIRST-EVER
disassembly of Dell's plaintext EC firmware (Latitude 5X90 1.41.0 PHCM bodies).

Everything below was derived from the 5X90 ec_1/ec_2 images in this repo
(collected/Latitude_5X90_1.41.0/) and is codified here so any future EC dump
(incl. the t.me/biosarchive/24189 archive, if it holds an EC read) can be
tripped through the same pipeline in seconds.

--- PHCM container (Dell EC update payload) ---
  dword[0] = 'PHCM' magic
  byte hdr[5]  bit7 (0x80) = body AES-sealed  (5X90: 0x01 -> PLAINTEXT;
              2019+ families: 0x81 -> sealed, engine unreadable)
  dword[4] = 'bt' boot entry (image-relative, Thumb, bit0 set)
  layout observed on 5X90 ec_1 (166784 B):
    file[0x00000:0x00080]  main PHCM header
    file[0x00080:0x20000]  CODE segment -> loads at 0x00110000  (Cortex-M4F)
    file[0x20000:0x20080]  2nd segment header
    file[0x20080:0x28B80]  DATA segment -> loads at 0x000F0000
  runtime address R  <->  file offset:
    CODE: file = R - 0x00110000 + 0x80
    DATA: file = R - 0x000F0000 + 0x20080   (verified: 72-char table at
          runtime 0x000F17A9 == file 0x21829 exactly)

--- EC host window (MEC mailbox) — decoded this cycle ---
  0x400F0110  command byte        (dispatchers at file 0xD868 / 0x914 / 0xE9C8)
  0x400F0111  sub-command / status
  0x400F0112  ready flag          (transport: 0x1C8B8 read / 0x1C8F0 write)
  0x400F0113  chunk length        (<=8 bytes per chunk)
  0x400F0114  data chunk (8 B)    0x17 on 0x110/0x111 = xfer handshake value
  Commands (password/session dispatcher, file 0xD868):
    0x21 reset session | 0x22/0x23 state | 0x24/0x25 mode
    0x26 PASSWORD SESSION (sub 0..8 via TBB @file 0xD7BC; verify/enroll paths)
    0x4D ack | 0x4E send 8B of enrolled block | 0x4F recv -> 0x0011899C
    0x50 recv into staging 0x001189C0 + compare | 0x51 send 2B
    0x5A SEND 34B of buffer 0x0011899C, XOR 0x85, into window from 0x400F0111
    0xB4 mode-verify
  Buffers (runtime): 0x0011899C rx {len,data..}, 0x001189C0 staging(32B),
    0x00119420 enrolled block (33B: len+32), 0x00118952 {len,16B},
    0x00118978 flags. Record store ops via subs 4/5/0x15 (0x15 = enrolled
    master per record-store triage in dell_ec_keygen --triage).
  Verifier (file 0xD5E8): 16 chars, table72[input[i] % 72] == staged[i];
    table72 @ runtime 0x000F17A9 (file 0x21829) = 72-char near-sequential
    alphabet; charset bitmap follows at 0x000F17F1 (file 0x21871).

--- New-suffix GENERATE engine status ---
  5X90 (2018, E7A8-era) = verify/enroll only; NO tag->response GENERATE
  (no C065AEAB GUID, no new family-byte table). All 2019+ EC update payloads
  are AES-sealed (hdr flag 0x80). The new-era engine still requires a real
  EC-internal dump (Step 5 doors) — this tool decodes one the moment it lands.

Usage:
  python3 dell_ec_engine_re.py --info <ec-bin> [more bins...]
  python3 dell_ec_engine_re.py --scan-plaintext <dir>
  python3 dell_ec_engine_re.py --xref <ec-bin>
  python3 dell_ec_engine_re.py --dispatch <ec-bin>
  python3 dell_ec_engine_re.py --family <ec-bin>
  python3 dell_ec_engine_re.py --disasm <ec-bin> --start 0xD868 --end 0xD9D0
  python3 dell_ec_engine_re.py --emul <ec-bin> --fn 0xCD8E   (unicorn; run one
      function at its FILE offset, capture mailbox writes)

Optional deps: capstone (disasm modes), unicorn (--emul). Everything else is
stdlib. Python 3.8+.
"""

import argparse
import math
import os
import re
import struct
import sys

# ---------------------------------------------------------------- constants

CODE_BASE = 0x00110000
CODE_FILE_START = 0x80
DATA_BASE = 0x000F0000
DATA_FILE_START = 0x20080

MAILBOX_LO, MAILBOX_HI = 0x400F0100, 0x400F0140

# new-suffix family bytes (low byte of the 16-bit suffix value)
FAMILY_BYTES = {0xC8: "8FC8", 0x1B: "CF1B", 0xBE: "9ABE", 0xE2: "3FE2", 0x58: "1B58"}

PHCM_HDR = 0x80


def rt2file(addr: int) -> int:
    """runtime address -> file offset (CODE/DATA segment map)."""
    if CODE_BASE <= addr < CODE_BASE + 0x20000:
        return addr - CODE_BASE + CODE_FILE_START
    if DATA_BASE <= addr < DATA_BASE + 0x10000:
        return addr - DATA_BASE + DATA_FILE_START
    return None


def file2rt(off: int) -> int:
    if CODE_FILE_START <= off < 0x20000:
        return CODE_BASE + off - CODE_FILE_START
    if off >= DATA_FILE_START:
        return DATA_BASE + off - DATA_FILE_START
    return None


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# ---------------------------------------------------------------- --info

def phcm_info(path: str):
    d = open(path, "rb").read()
    name = os.path.basename(path)
    if d[:4] != b"PHCM":
        print(f"{name}: not a PHCM payload (magic {d[:4]!r})")
        return
    ver = struct.unpack_from("<I", d, 4)[0]
    bt = struct.unpack_from("<I", d, 16)[0]
    sealed = bool(ver & 0x00800000)
    body = d[PHCM_HDR:]
    ent = entropy(body[:65536])
    fp = d.count(bytes.fromhex("10010F40"))       # refs to engine mailbox 0x400F0110
    fam = family_table_offsets(d)
    print(f"{name}: sz={len(d)} ver={ver:08X} seal_flag={'YES (AES)' if sealed else 'no (PLAINTEXT)'}"
          f" bt=0x{bt:X} body_entropy={ent:.2f}")
    print(f"   mailbox 0x400F0110 literal refs: {fp}   family-byte tables: "
          f"{[hex(o) for o in fam[:4]] or 'none'}")
    if not sealed and fp:
        print("   VERDICT: plaintext body with password-session engine — disassemble/`--xref` me")
    elif sealed:
        print("   VERDICT: sealed body (expected for 2019+ update packages) — engine not readable")
    # segment sizes
    if len(d) > DATA_FILE_START:
        print(f"   segments: code file[0x80:0x20000)->0x{CODE_BASE:08X} "
              f"data file[0x{DATA_FILE_START:X}:)->0x{DATA_BASE:08X} ({len(d)-DATA_FILE_START} B)")


# ------------------------------------------------------- --scan-plaintext

def family_table_offsets(d: bytes):
    """16-byte windows containing all five new-suffix family bytes.
    Fast path: anchor on the rarest byte (0xE2) and check only its windows."""
    need = set(FAMILY_BYTES)
    out, start = [], 0
    anchor = bytes([0xE2])
    while len(out) < 64:
        i = d.find(anchor, start)
        if i < 0:
            break
        start = i + 1
        lo = max(0, i - 15)
        if need <= set(d[lo:i + 1]):
            out.append(lo)
    return out


def scan_plaintext(root: str):
    """Walk a tree; report every file that could contain a readable engine."""
    hits = 0
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                if os.path.getsize(p) > 32 * 1024 * 1024:
                    continue
                d = open(p, "rb").read()
            except OSError:
                continue
            phcm = d[:4] == b"PHCM"
            fp = d.count(bytes.fromhex("10010F40"))
            fam = family_table_offsets(d)
            gen = d.count(b"\xc0\x65\xae")            # GENERATE GUID prefix
            vec = 0
            for i in range(0, len(d) - 8, 4):          # Cortex-M vector table
                w0, w1 = struct.unpack_from("<II", d, i)
                if 0x20000000 <= w0 < 0x20080000 and (w1 & 1) and w1 < 0x200000:
                    vec += 1
                    break
            if phcm or fp or fam or gen:
                ent = entropy(d[:65536]) if len(d) > 4096 else entropy(d)
                sealed = "?" if not phcm else ("YES" if struct.unpack_from('<I', d, 4)[0] & 0x00800000 else "no")
                print(f"  {'PHCM' if phcm else 'raw '} sealed={sealed:3s} ent={ent:4.2f} "
                      f"fp0110={fp:3d} family={len(fam)} genGUID={gen}  {p}")
                hits += 1
    print(f"{hits} candidate(s) under {root}")


# ---------------------------------------------------------------- --xref

def find_all(d: bytes, pat: bytes, limit: int = 4096):
    out, start = [], 0
    while len(out) < limit:
        i = d.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def function_start(d: bytes, off: int, back: int = 0x200):
    """scan back for push {..., lr} (0xB5xx) or push.w (0xE92D)"""
    for b in range(0, back, 2):
        p = off - b
        if p < 2:
            return None
        w = struct.unpack_from("<H", d, p - 2)[0]
        if 0xB500 <= w <= 0xB5FF:
            return p - 2
        if w == 0xE92D:
            return p - 2
    return None


def xref(path: str):
    d = open(path, "rb").read()
    print(f"=== mailbox window xrefs in {os.path.basename(path)} ===")
    rows = []
    for a in range(MAILBOX_LO, MAILBOX_HI, 4):
        for i in find_all(d, struct.pack("<I", a), 256):
            rows.append((i, a))
    # byte-addressed variants too (0x400F0111..0x400F0113 are individually hot)
    rows.sort()
    for i, a in rows:
        fn = function_start(d, i)
        rt = f" (rt 0x{file2rt(i):08X})" if file2rt(i) else ""
        print(f"  literal 0x{a:08X} @file 0x{i:X}{rt}"
              + (f"   <- fn ~0x{fn:X}" if fn else ""))


# ------------------------------------------------------------ --dispatch

def dispatch(path: str):
    """find `ldrb rX,[rY]; cmp rX,#imm; beq/bhi` dispatcher chains on the
    mailbox command byte — done statically: locate every cmp #imm that is
    preceded within 0x10 bytes by a load of a 0x400F0110-literal pointer."""
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    except ImportError:
        sys.exit("capstone required for --dispatch (pip install capstone)")
    d = open(path, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    # every 0x400F0110 literal + the fn that dereferences it
    ptrs = find_all(d, struct.pack("<I", MAILBOX_LO), 256)
    print(f"=== command dispatchers ({len(ptrs)} loads of 0x400F0110) ===")
    seen_fn = set()
    for lit in ptrs:
        # find code windows that LDR this literal then LDRB + CMP imm
        for wstart in range(max(0, lit - 0x400), min(len(d), lit + 0x100), 2):
            code = d[wstart:wstart + 0x60]
            n = 0
            cmds = set()
            for ins in md.disasm(code, wstart):
                if ins.mnemonic == "ldr" and "[pc" in ins.op_str:
                    try:
                        imm = int(ins.op_str.split("#")[-1].rstrip("]"), 0)
                        la = ((ins.address + 4) & ~3) + imm
                        if la == lit:
                            n += 1
                    except Exception:
                        pass
                if ins.mnemonic == "cmp" and ins.op_str.startswith("r"):
                    try:
                        v = int(ins.op_str.split("#")[1], 0)
                        if 1 <= v <= 0xFF:
                            cmds.add(v)
                    except Exception:
                        pass
            if n and len(cmds) >= 4:
                fn = function_start(d, wstart)
                if fn and fn not in seen_fn:
                    seen_fn.add(fn)
                    print(f"  fn @file 0x{fn:X} (rt 0x{file2rt(fn) or 0:08X}): "
                          f"{len(cmds)} cmp-imms: {sorted(hex(c) for c in cmds)}")
                    break


# ---------------------------------------------------------------- --family

def family(path: str):
    d = open(path, "rb").read()
    fam = family_table_offsets(d)
    if not fam:
        print("no new-suffix family-byte table found "
              "(expected: sealed bodies, or pre-2019 EC without new families)")
        return
    for off in fam[:16]:
        print(f"  family table @file 0x{off:X}: {d[off:off+16].hex()}")


# ---------------------------------------------------------------- --disasm

def disasm(path: str, start: int, end: int):
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    except ImportError:
        sys.exit("capstone required for --disasm (pip install capstone)")
    d = open(path, "rb").read()
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    for i in md.disasm(d[start:end], start):
        note = ""
        if "[pc" in i.op_str:
            try:
                imm = int(i.op_str.split("#")[-1].rstrip("]"), 0)
                la = ((i.address + 4) & ~3) + imm
                if la + 4 <= len(d):
                    v = struct.unpack_from("<I", d, la)[0]
                    if MAILBOX_LO <= v < MAILBOX_HI:
                        note = f"   <MAILBOX+0x{v-0x400F0100:x}>"
                    elif 0x400F0000 <= v < 0x40100000:
                        note = f"   <MMIO 0x{v:08X}>"
                    elif rt2file(v) is not None:
                        note = f"   <rt 0x{v:08X} = file 0x{rt2file(v):X}>"
                    else:
                        note = f"   <0x{v:08X}>"
            except Exception:
                pass
        print(f"  {i.address:06x}: {i.mnemonic:9s} {i.op_str}{note}")


# ---------------------------------------------------------------- --emul

def emul(path: str, fn_off: int, preloads, timeout_ins: int = 2_000_000):
    """Run one Cortex-M function (given as FILE offset) under unicorn with the
    decoded segment map; capture every write into the mailbox window.
    preloads: list of (runtime_addr, bytes) written before the call."""
    try:
        from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS,
                            UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ)
        from unicorn.arm_const import (UC_ARM_REG_SP, UC_ARM_REG_LR,
                                       UC_ARM_REG_PC)
    except ImportError:
        sys.exit("unicorn required for --emul (pip install unicorn)")
    d = open(path, "rb").read()
    PAGE = 0x1000
    code = d[CODE_FILE_START:DATA_FILE_START - PHCM_HDR]
    data = d[DATA_FILE_START:]
    base = CODE_BASE
    fn_rt = file2rt(fn_off)
    if fn_rt is None:
        sys.exit("function offset outside known segments")
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    uc.mem_map(base, ((len(code) + PAGE - 1) // PAGE) * PAGE)
    uc.mem_write(base, code)
    uc.mem_map(DATA_BASE, ((len(data) + PAGE - 1) // PAGE) * PAGE)
    uc.mem_write(DATA_BASE, data)
    uc.mem_map(0x20000000, 0x20000)                 # SRAM
    uc.mem_map(0x40000000, 0x100000)                # MMIO (all peripherals)
    uc.mem_map(0xE0000000, 0x100000)                # NVIC/System (spins may poll)

    writes = []
    reads = []

    def hook_write(uc_, _a, addr, size_, value, _u):
        if MAILBOX_LO <= addr < MAILBOX_HI:
            writes.append((addr, value & ((1 << (8 * size_)) - 1), size_))

    def hook_read(uc_, _a, addr, size_, value, _u):
        if MAILBOX_LO <= addr < MAILBOX_HI:
            reads.append((addr, size_))

    uc.hook_add(UC_HOOK_MEM_WRITE, hook_write)
    uc.hook_add(UC_HOOK_MEM_READ, hook_read)

    for addr, blob in preloads:
        uc.mem_write(addr, blob)

    STOP = 0x00100000
    uc.mem_map(STOP, 0x1000)
    uc.mem_write(STOP, b"\x00\xbe")                 # bkpt -> undefined? use infinite loop: b .
    uc.mem_write(STOP, b"\xfe\xe7")                 # b . (loop forever)
    uc.reg_write(UC_ARM_REG_SP, 0x20008000)
    uc.reg_write(UC_ARM_REG_LR, STOP)
    try:
        uc.emu_start(fn_rt | 1, STOP, count=timeout_ins)
    except Exception as e:
        print(f"emulation stopped: {e}")
    print(f"ran fn file 0x{fn_off:X} (rt 0x{fn_rt:08X}); "
          f"{len(writes)} mailbox writes, {len(reads)} mailbox reads")
    for addr, val, size_ in writes[:64]:
        print(f"  write 0x{addr:08X} (+0x{addr-0x400F0110:+x}) = 0x{val:02x}")
    if len(writes) > 64:
        print(f"  ... {len(writes)-64} more")
    return writes


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--info", nargs="+", metavar="BIN")
    ap.add_argument("--scan-plaintext", nargs="+", metavar="DIR")
    ap.add_argument("--xref", metavar="BIN")
    ap.add_argument("--dispatch", metavar="BIN")
    ap.add_argument("--family", metavar="BIN")
    ap.add_argument("--disasm", metavar="BIN")
    ap.add_argument("--emul", metavar="BIN")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--end", type=lambda x: int(x, 0), default=0x200)
    ap.add_argument("--fn", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--preload", action="append", default=[],
                    metavar="ADDR=HEXBYTES",
                    help="e.g. --preload 0x00118978=01 (runtime address)")
    a = ap.parse_args()

    if a.info:
        for p in a.info:
            phcm_info(p)
    if a.scan_plaintext:
        for root in a.scan_plaintext:
            scan_plaintext(root)
    if a.xref:
        xref(a.xref)
    if a.dispatch:
        dispatch(a.dispatch)
    if a.family:
        family(a.family)
    if a.disasm:
        disasm(a.disasm, a.start, a.end)
    if a.emul:
        if a.fn is None:
            sys.exit("--emul needs --fn 0xFILE_OFFSET")
        preloads = []
        for spec in a.preload:
            addr_s, hex_s = spec.split("=", 1)
            preloads.append((int(addr_s, 0), bytes.fromhex(hex_s)))
        emul(a.emul, a.fn, preloads)


if __name__ == "__main__":
    main()
