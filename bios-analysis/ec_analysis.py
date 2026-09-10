#!/usr/bin/env python3
"""ec_analysis.py — Dell EC firmware (PHCM container) analysis toolkit.

Developed against the Latitude 5X90 EC firmware (v1.00.51, 2023), which ships
as PLAINTEXT ARM Cortex-M Thumb code inside a PHCM container — unlike the
OptiPlex 3090 / Latitude 5300 ECs whose PHCM bodies are AES-encrypted.

Established memory map (Latitude_5X90_1.41.0 EC 1.00.51):
    flash 0x00000000..0x0FFFFF (code 0xD0000..0xF0000+, data 0xF0000..0xFA300)
    RAM   0x00100000.. (mailbox window @ 0x118F90, service record @ 0x118FAC,
                        per-service flags @ 0x118FAC + 4*svc)
    MMIO  0x40000000.. (Nuvoton NPCX-style modules; eSPI I/O window @ 0x400F3400)

Key structures reversed (see REPORT.md section 12):
    * PHCM header: 128 B (5X90) / 192 B (3090); body = n x 64 B chunks,
      n @ +0x10 (u32), header size @ +0x14 (u32).
    * Host mailbox: port 0x910 (index) / 0x911 (data); eSPI I/O trap configured
      by init fn @0xD19F8 (ranges {0x2E, 0x910, 0xB10, 0x80} into window regs
      +0x334/+0x33C/+0x34C/+0x350 of MMIO 0x400F3400; RAM window ptr @ +0x348).
    * Port-0x910 IRQ engine @0xEFEBC: checks trapped port == 0x910, state
      machine (0/1/2) with 0x78 sync byte, 8-byte collects into the window,
      byte-exact comparisons (verify path).
    * Service layer: task loop reads service u16 at window+0x1C (0x118FAC),
      dispatches via table @0xF1FDC: handler trampoline @ entry+0x444,
      subscriber list @ entry+0x438 (28-byte entries, EVEN service IDs valid).
      Trampolines: 0xDFF99 (4-byte fn list), 0xDFF6D / 0xE000D (variants).
    * Service 0x22 (BIOS mailbox cmd 0x21 - password challenge family):
      single subscriber 0xDEBBC (state gate 0xED/0xEE/0xC3).
      Service 0x18 (cmd 0x17 data transfer): 8 subscribers (list @0xF2F10).
    * EC also implements KCDSA/ECDSA signature verification
      ("VerifyEcKcdsaSignature", "ecsdsa_verify_from_A0") — the challenge
      response may be ECC-signed with a per-machine key.

Usage:
    python3 ec_analysis.py <ec-bin>            # basic info + strings
    python3 ec_analysis.py <ec-bin> --xref A   # find LDR users of literal A
    python3 ec_analysis.py <ec-bin> --services # dump the service table
    python3 ec_analysis.py <ec-bin> --dis A N  # disassemble N bytes at addr A

Addresses are EC-flash addresses (body offset + 0xD0000 for this image).
"""
import struct
import sys
import re

# ---------------------------------------------------------------- PHCM parse

def parse_phcm(data):
    if data[:4] != b"PHCM":
        raise ValueError("not a PHCM container")
    ver = data[4:8].hex()
    n = struct.unpack_from("<I", data, 0x10)[0]
    hs = struct.unpack_from("<I", data, 0x14)[0]
    return {"ver": ver, "n": n, "hsize": hs, "body": data[hs:len(data) - hs]}


# ---------------------------------------------------------------- disassembly

def get_disassembler():
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    return md


def disasm(body, base, addr, nbytes):
    md = get_disassembler()
    lo = addr - base
    for ins in md.disasm(body[lo:lo + nbytes], addr):
        print(f"  {ins.address:#08x}: {ins.mnemonic:<10s} {ins.op_str}")


# ---------------------------------------------------------------- xref tools

def find_ldr_users(body, base, value, lo=None, hi=None):
    """All LDR rX,[pc,#imm] whose literal VALUE == value."""
    users = []
    lo = lo or base
    hi = hi or base + len(body)
    p = lo - base
    end = hi - base
    while p < end - 4:
        h = struct.unpack_from("<H", body, p)[0]
        if (h >> 11) == 0b01001:
            imm = (h & 0xFF) * 4
            tgt = ((base + p + 4) & ~3) + imm
            if base <= tgt < base + len(body):
                if struct.unpack_from("<I", body, tgt - base)[0] == value:
                    users.append(base + p)
        if (h & 0xF8FF) in (0xF8DF, 0xF85F):
            imm = struct.unpack_from("<H", body, p + 2)[0]
            tgt = ((base + p + 4) & ~3) + imm
            if base <= tgt < base + len(body):
                if struct.unpack_from("<I", body, tgt - base)[0] == value:
                    users.append(base + p)
        p += 2
    return users


def dump_service_table(body, base, T=0xF1FDC, count=0x38):
    """Service table @0xF1FDC: 28-byte entries; handler @ entry+0x444
    (trampoline), subscriber list @ entry+0x438. Valid = odd code ptr."""
    def u32(a):
        return struct.unpack_from("<I", body, a - base)[0]
    print(f"service table @ {T:#x} (handler=entry+0x444, list=entry+0x438)")
    for svc in range(count):
        ent = T + 0x1C * svc
        if ent + 0x448 > base + len(body):
            break
        h = u32(ent + 0x444)
        lst = u32(ent + 0x438)
        if h == 0 and lst == 0:
            continue
        valid = (0xD0000 <= h < 0xF0000) and (h & 1)
        if valid and not (0xE2000 <= lst < base + len(body)):
            # list pointer must be in the image
            print(f"  svc 0x{svc:02x}: trampoline {h:#x}, list {lst:#x} (bad list)")
            continue
        if valid:
            print(f"  svc 0x{svc:02x}: trampoline {h:#x}, list {lst:#x}")
            # dump list as 4-byte fn pointers (0xDFF99 semantics)
            for i in range(12):
                if lst + 4 * i + 4 > base + len(body):
                    break
                fn_ = u32(lst + 4 * i)
                if fn_ == 0:
                    break
                tag = "CODE" if (0xD0000 <= fn_ < 0xF0000 and fn_ & 1) else "?"
                print(f"      fn[{i}] = {fn_:#x} {tag}")


# ---------------------------------------------------------------- main

def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        return
    data = open(args[0], "rb").read()
    ph = parse_phcm(data)
    base = 0xD0000  # flash base of the PHCM body in this image
    print(f"PHCM ver={ph['ver']} chunks={ph['n']} hsize={ph['hsize']} "
          f"body={len(ph['body'])}")

    if args[1] == "--dis" and len(args) >= 4:
        disasm(ph["body"], base, int(args[2], 16), int(args[3]))
    elif args[1] == "--xref" and len(args) >= 3:
        val = int(args[2], 16)
        for u in find_ldr_users(ph["body"], base, val):
            print(f"  {u:#x}")
    elif args[1] == "--services":
        dump_service_table(ph["body"], base)
    elif args[1] == "--strings":
        for m in re.finditer(rb"[\x20-\x7e]{8,}", ph["body"]):
            print(f"  {m.start() + base:#x}: {m.group(0).decode()}")
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
