#!/usr/bin/env python3
"""pw_fw_exec.py -- execute the REAL Dell pw-module CF1B derivation in an
x86-64 emulator (unicorn) and prove the delivered master password.

The OptiPlex 3090 BIOS password module (pw_4, PDB
8bfd0c848dd9ffcb525e6d12a9da182c7e576b6f.pdb, rebuilt per era) contains the
modern keygen API:

    NTSTATUS api(char *serial, u64 serial_len, char *out, u64 out_len,
                 u16 family, u32 map_flag)

    2.0.7  pw_4_42496.efi: API @RVA 0x926C, dispatch lookup @0x7FA0
    2.27.0 pw_4_43008.efi: API @RVA 0x9408, dispatch lookup @0x8060

Dispatch table (identical in both eras, @0xA9C0 / @0xA9D0):
{8FC8 stub, E7A8 live, END} -- CF1B is NOT a member.

The era gate is a single constant: the lookup's not-found sentinel.
2.0.7 returns 0xFF  -> caller's `cmp rax,0xff; je` reaches the hardcoded
                       BF97 fallback -> CF1B master generated locally.
2.27.0 returns 0xFFFF -> `cmp rax,0xff` never matches -> descriptor path ->
                       EFI_INVALID_PARAMETER; CF1B verification is delegated
                       to the EC (see FINDINGS_5X90_EC.md / REPORT.md §11).
The BF97 fallback itself (mov ebp,0xBF97 ...) still ships unchanged in
2.27.0 (0x94BA) -- this harness proves it still produces the identical
password when its branch is taken.

Usage:
    python3 pw_fw_exec.py                # self-test (H2FS5S3 + cross-checks)
    python3 pw_fw_exec.py <TAG> <FAM>    # custom run, e.g. H2FS5S3 CF1B
"""
import struct
import sys

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
from unicorn.x86_const import (
    UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RAX,
)

MOD_207 = "collected/OptiPlex_3090_2.0.7/pw_4_42496.efi"
MOD_227 = "collected/OptiPlex_3090_2.27.0/pw_4_43008.efi"
API_207 = 0x926C
API_227 = 0x9408
JE_OFF = 0x33                    # `je <fallback>` byte offset from API start
EFI_INVALID_PARAMETER = 0x8000000000000002

SENTINEL = 0x900000              # magic return address
STACK = 0x100000
HEAP = 0x200000


class Mod:
    """Minimal PE loader + unicorn x86-64 caller for the pw module."""

    def __init__(self, path, api_rva):
        self.path = path
        d = self.d = open(path, "rb").read()
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE"
        self.imgbase = struct.unpack_from("<Q", d, e_lfanew + 24 + 24)[0]
        nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
        optsz = struct.unpack_from("<H", d, e_lfanew + 20)[0]
        self.sections = []
        so = e_lfanew + 24 + optsz
        for i in range(nsec):
            off = so + i * 40
            nm = d[off:off + 8].rstrip(b"\0").decode()
            vsz, va, rsz, ro = struct.unpack_from("<IIII", d, off + 8)
            self.sections.append((nm, va, vsz, ro, rsz))
        self.api_rva = api_rva
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc = self.uc
        uc.mem_map(0, 0x100000)
        uc.mem_map(STACK, 0x20000)
        uc.mem_map(HEAP, 0x10000)
        for nm, va, vsz, ro, rsz in self.sections:
            uc.mem_write(self.imgbase + va, d[ro:ro + rsz])

    def call_api(self, serial: bytes, out_len: int, family: int, map_flag: int,
                 force_fallback=False):
        """Run the keygen API; returns (status, out_bytes).

        force_fallback: flip the caller's `je <fallback>` (API+0x33) into an
        unconditional `jmp` -- i.e. emulate 2.0.7 not-found semantics
        (sentinel 0xFF instead of 0xFFFF).  Demonstrates the still-shipped
        2.27.0 BF97 fallback runs and produces the identical password.
        """
        uc = self.uc
        uc.mem_write(HEAP, b"\x00" * 0x10000)
        uc.mem_write(HEAP, serial)
        sp = STACK + 0x10000 - 0x200
        uc.mem_write(sp + 0x00, struct.pack("<Q", SENTINEL))
        uc.mem_write(sp + 0x28, struct.pack("<HH", family, 0))   # 5th arg
        uc.mem_write(sp + 0x30, struct.pack("<I", map_flag))     # 6th arg
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RCX, HEAP)             # serial
        uc.reg_write(UC_X86_REG_RDX, len(serial))      # serial_len
        uc.reg_write(UC_X86_REG_R8, HEAP + 0x100)      # out
        uc.reg_write(UC_X86_REG_R9, out_len)           # out_len
        patch_addr = None
        orig_byte = None
        if force_fallback:
            patch_addr = self.imgbase + self.api_rva + JE_OFF
            orig_byte = bytes(uc.mem_read(patch_addr, 1))
            assert orig_byte == b"\x74", \
                f"expected je at {patch_addr:#x}, got {orig_byte!r}"
            uc.mem_write(patch_addr, b"\xeb")          # je -> jmp
        try:
            uc.emu_start(self.imgbase + self.api_rva, SENTINEL,
                         timeout=0, count=20_000_000)
        except UcError as e:
            return f"EXC {e}", None
        finally:
            if patch_addr is not None:
                uc.mem_write(patch_addr, orig_byte)
        status = uc.reg_read(UC_X86_REG_RAX)
        out = bytes(uc.mem_read(HEAP + 0x100, out_len)) if out_len else b""
        return status, out


def find_bf97_constants(path):
    """Locate `mov ebp, 0xBF97` (BD 97 BF 00 00) sites in .text."""
    d = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", d, e_lfanew + 20)[0]
    so = e_lfanew + 24 + optsz
    hits = []
    for i in range(nsec):
        off = so + i * 40
        if d[off:off + 6] == b".text\0":
            vsz, va, rsz, ro = struct.unpack_from("<IIII", d, off + 8)
            code = d[ro:ro + rsz]
            j = code.find(b"\xbd\x97\xbf\x00\x00")
            while j != -1:
                hits.append(va + j)
                j = code.find(b"\xbd\x97\xbf\x00\x00", j + 1)
    return hits


def selftest():
    sys.path.insert(0, ".")
    import dell_keygen as dk
    ok = True

    for path in (MOD_207, MOD_227):
        hits = find_bf97_constants(path)
        print(f"{path.split('/')[-2]}/{path.split('/')[-1]}: "
              f"`mov ebp,0xBF97` at RVA {[hex(h) for h in hits]}")
        ok &= bool(hits)

    # ---- 2.0.7: CF1B reaches the BF97 fallback naturally ----------------
    m = Mod(MOD_207, api_rva=API_207)
    print(f"\n== 2.0.7 pw_4 (API @{API_207:#x}) -- CF1B fallback, natural path ==")
    status, out = m.call_api(b"H2FS5S3", 16, 0xCF1B, 1)
    got = out.rstrip(b"\x00").decode(errors="replace") if out else None
    print(f"  H2FS5S3 + family 0xCF1B -> status={status:#x} out={got!r}")
    ok &= (status == 0 and got == "shzNyjGRzRN2LLzL")

    for tag in ("1A2B3C4", "7QH8602", "ZZ9ZZ9Z"):
        st, o = m.call_api(tag.encode(), 16, 0xCF1B, 1)
        fw = o.rstrip(b"\x00").decode(errors="replace") if o else None
        py = dk.keygen_cf1b(tag, verbose=False)
        print(f"  {tag} CF1B -> firmware={fw!r} python={py!r} "
              f"{'MATCH' if fw == py else 'MISMATCH'}")
        ok &= fw == py

    st, o = m.call_api(b"H2FS5S3", 16, 0x8FC8, 1)
    print(f"  H2FS5S3 + 0x8FC8 (table stub) -> status={st:#x} "
          f"(expect EFI_INVALID_PARAMETER)")
    ok &= st == EFI_INVALID_PARAMETER

    st, o = m.call_api(b"H2FS5S3", 16, 0xCF1B, 0)
    print(f"  H2FS5S3 CF1B map_flag=0 raw encoder bytes: "
          f"{o.hex() if o else None}")

    # ---- 2.27.0: the gate + the intact fallback --------------------------
    m = Mod(MOD_227, api_rva=API_227)
    print(f"\n== 2.27.0 pw_4 (API @{API_227:#x}) -- era gate + intact fallback ==")
    st, o = m.call_api(b"H2FS5S3", 16, 0xCF1B, 1)
    print(f"  natural path (sentinel is 0xFFFF) -> status={st:#x} "
          f"(descriptor path: EFI_INVALID_PARAMETER; generation disabled)")
    ok &= st == EFI_INVALID_PARAMETER
    # fresh instance: the descriptor-path run dirties module state (curiosity:
    # the 0x908C path mutates a .data global), so emulate a cold module
    m = Mod(MOD_227, api_rva=API_227)
    st, o = m.call_api(b"H2FS5S3", 16, 0xCF1B, 1, force_fallback=True)
    got = o.rstrip(b"\x00").decode(errors="replace") if o else None
    print(f"  fallback forced (2.0.7 semantics)  -> status={st:#x} out={got!r}")
    ok &= (st == 0 and got == "shzNyjGRzRN2LLzL")

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


def main():
    if len(sys.argv) >= 3:
        tag, fam = sys.argv[1], sys.argv[2].upper()
        fam_v = int(fam, 16)
        m = Mod(MOD_207, api_rva=API_207)
        status, out = m.call_api(tag.encode(), 16, fam_v, 1)
        print(f"status={status:#x} "
              f"password={out.rstrip(chr(0).encode()).decode()!r}")
        return 0
    return selftest()


if __name__ == "__main__":
    raise SystemExit(main())
