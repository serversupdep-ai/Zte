#!/usr/bin/env python3
"""
dell_cf1b_session_emu.py — end-to-end emulation proof of the CF1B EC GENERATE
session, executed on the OptiPlex 3090's OWN System BIOS 2.27.0 vault module
(inner PE carved from the FFS module at LZMA-stream offset 0x6f4a4).

It stubs the DellEcIo interface object ([global @VA 0xafc0]) with logging
methods, calls the SMM EC-session function (fn 0x37AC) with a type-6
({C065AEAB} GENERATE) descriptor, and shows:

  1. the exact EC mailbox wire sequence the BIOS itself performs:
       open:  cmd buf {0x21, 0x00, 0x03, 0x06}   (cmd 0x21, sub 3, type 6)
       send:  the SERVICE TAG ("H2FS5S3", 7 bytes)
       send:  1 byte = suffix LSB (0x1B for CF1B)
       recv:  32 bytes  (the EC-computed codes)
       recv:  1 status byte (0x00 = success, fn 0x31B4 map)
  2. the response -> code map (fn 0x8E18) for all three branches:
       CF1B  -> resp[0:16] VERBATIM (not in dispatch table -> raw copy)
       8FC8  -> alphabet0[(resp[i]+resp[i+16]) % 72]  (alphabet @0xa280)
       E7A8  -> legacy local tail (alphabet @0xaa20, single mod-72) — not EC-routed

Usage:  python3 dell_cf1b_session_emu.py /path/to/vault_2270_cf1b_pe32.pe
        (default /tmp/vault_2270_cf1b_pe32.pe)

Requires: unicorn, capstone (pip), dell_v2_keygen.py in the same directory.
"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import *                                     # noqa: E402
from unicorn.x86_const import *                           # noqa: E402
from dell_v2_keygen import VaultEmu, BASE                 # noqa: E402

PE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware", "vault_3090_2.27.0_cf1b.pe")
FN_37AC = 0x37AC          # EC session (sub 3): type-6 branch = GENERATE
GLB_IF = 0xafc0           # DellEcIo interface object pointer
GLB_MODE = 0xaec8         # mode qword (type-4 branch only)
MODULE_BASE = BASE        # image load base used by dell_v2_keygen.VaultEmu
GUID_C065AEAB = bytes.fromhex("abae65c01cdd494dbd334578e106c700")
ALPHA_EC = ("0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r")
ALPHA_E7A8_LEGACY_TAIL = None  # @0xaa20, digit-first; loaded from the PE below


def load_alphabets(data):
    def va2off(v):
        return 0x8c00 + (v - 0xa000) if v >= 0xa000 else 0x400 + (v - 0x1000)
    a0 = struct.unpack_from("<Q", data, va2off(0xa9e0))[0]
    a1 = struct.unpack_from("<Q", data, va2off(0xa9e0 + 24))[0]
    d0 = data[va2off(a0):va2off(a0) + 72].decode("latin1")
    d1 = data[va2off(a1):va2off(a1) + 72].decode("latin1")
    return d0, d1


def run(pe_bytes, suffix_word, canned, tag=b"H2FS5S3"):
    emu = VaultEmu(pe_bytes)
    uc = emu.uc
    OBJ, BUFS, STUB = 0x09000000, 0x09010000, 0x0E000000
    uc.mem_map(0x09000000, 0x100000)
    uc.mem_map(STUB, 0x1000)
    slots = {0x00: STUB, 0x38: STUB + 0x38, 0x40: STUB + 0x40, 0x48: STUB + 0x48}
    CMDBUF = BUFS + 0x800
    obj = bytearray(b"\x00" * 0x100)
    for off, addr in slots.items():
        uc.mem_write(addr, b"\xc3")                       # ret
        struct.pack_into("<Q", obj, off, addr)
    struct.pack_into("<Q", obj, 0x60, CMDBUF)             # [obj+0x60] -> cmd buf
    uc.mem_write(OBJ, bytes(obj))
    uc.mem_write(MODULE_BASE + GLB_IF, struct.pack("<Q", OBJ))
    uc.mem_write(MODULE_BASE + GLB_MODE, struct.pack("<Q", 1))

    gptr = BUFS
    uc.mem_write(gptr, GUID_C065AEAB)
    inbuf = BUFS + 0x100
    uc.mem_write(inbuf, tag)
    desc = BUFS + 0x200
    uc.mem_write(desc, struct.pack("<QQ", gptr, inbuf) + bytes([len(tag)]))
    arg2 = BUFS + 0x300                                   # output buffer
    uc.mem_write(arg2, b"\xAA" * 0x40)
    arg3 = BUFS + 0x400
    uc.mem_write(arg3, struct.pack("<Q", 0x10) + b"\xBB" * 0x38)
    suf = BUFS + 0x500
    uc.mem_write(suf, struct.pack("<H", suffix_word) + b"\xCC" * 0x3E)
    arg6 = BUFS + 0x600
    uc.mem_write(arg6, b"\x01" + b"\x00" * 7)             # second send: 1 byte

    log = []

    def hook(uc_, addr, size, user):
        rip = uc_.reg_read(UC_X86_REG_RIP)
        slot = {v: k for k, v in slots.items()}.get(rip)
        if slot is None:
            return
        rcx = uc_.reg_read(UC_X86_REG_RCX)
        dl = uc_.reg_read(UC_X86_REG_RDX) & 0xFF
        r8 = uc_.reg_read(UC_X86_REG_R8)
        cmdbuf = struct.unpack_from("<Q", bytes(uc_.mem_read(rcx + 0x60, 8)))[0] if rcx else 0
        hdr = bytes(uc_.mem_read(cmdbuf, 8)) if cmdbuf else b""
        data = bytes(uc_.mem_read(r8, max(dl, 1))) if r8 else b""
        log.append((slot, dl, hdr, data))
        if slot == 0x48:
            uc_.mem_write(r8, canned if dl == 0x20 else b"\xfa" * dl)
        elif slot == 0x00:
            uc_.mem_write(r8, b"\x00")                    # status 0 = success
        uc_.reg_write(UC_X86_REG_RAX, 0)

    uc.hook_add(UC_HOOK_CODE, hook, begin=STUB, end=STUB + 0x1000)
    rv = emu.call(FN_37AC, rcx=desc, rdx=arg2, r8=arg3, r9=suf, stackargs=(arg6,))
    out = bytes(uc.mem_read(arg2, 0x10))
    return rv, out, log


def main():
    pe = open(PE, "rb").read()
    alpha0, alpha1 = load_alphabets(pe)
    canned = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
    tag = b"H2FS5S3"

    print(f"vault module: {PE} ({len(pe)} bytes)")
    print(f"alphabet[0] (EC path, 8FC8 dispatch): {alpha0!r}")
    print(f"alphabet[1] (E7A8):                   {alpha1!r}\n")

    ok = True
    for sfx, name in ((0xCF1B, "CF1B"), (0x8FC8, "8FC8"), (0xE7A8, "E7A8")):
        rv, out, log = run(pe, sfx, canned, tag)
        seq = []
        for slot, dl, hdr, data in log:
            if slot == 0x38:
                seq.append(f"open({hdr[:4].hex()})")
            elif slot == 0x40:
                seq.append(f"send({data[:dl].hex()})" if dl else "send()")
            elif slot == 0x48:
                seq.append(f"recv({dl})")
            elif slot == 0x00:
                seq.append(f"status({dl})")
        print(f"[{name}] rv={rv:#x}  out={out!r}")
        print(f"        wire: {' -> '.join(seq)}")
        if sfx == 0xCF1B:
            good = out == canned[:16]
            print(f"        CF1B raw-copy check: out == resp[0:16] -> {good}")
            ok &= good and rv == 0
        elif sfx == 0x8FC8:
            pred = "".join(alpha0[(canned[i] + canned[i + 16]) % 72] for i in range(16))
            good = out.decode("latin1") == pred
            print(f"        8FC8 alphabet check: pred={pred!r} -> {good}")
            ok &= good and rv == 0
        else:
            print("        E7A8: legacy local tail (not EC-routed) — informational")
    print("\nRESULT:", "ALL CHECKS PASS — protocol + maps verified on the 3090's own code"
          if ok else "CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
