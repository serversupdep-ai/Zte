#!/usr/bin/env python3
"""dell_cf1b_r.py — CF1B-exclusive password arithmetic (no legacy algorithm).

Implements exactly what CF1B's own firmware does (CF1B_FINDINGS.md §2,
OptiPlex 3090 2.27.0/2.30.0 pw_4, instruction-confirmed):

    X = SHA256(pw[0..16] || salt)          # fn 0x1BB4, salt @RVA 0xA658
    Y = SHA256(X || salt)                  # the BIOS's expected EC response
    PASS iff R == Y                        # R = 32-byte EC response

where salt = the 4 raw bytes 8D FC 7B 25.

Modes:
    --pw <password>            show X and Y for a candidate
    --grind --R <hex> [...]    brute-force short passwords against a known R
                               (R is readable on the authorized machine with
                               dell_cf1b_probe.c — it is returned before the
                               PASS/FAIL comparison)
    --selftest                 validate the Python X against the REAL firmware
                               function 0x1BB4 executed under unicorn x86-64

The grind is a plain double-SHA-256 preimage over a charset — CF1B's own
arithmetic; only viable for short passwords.
"""
import hashlib
import itertools
import sys

SALT = bytes.fromhex("8dfc7b25")
MOD_227 = "collected/OptiPlex_3090_2.27.0/pw_4_43008.efi"
FN_1BB4 = 0x1BB4


def pw16(pw: str) -> bytes:
    """Password zero-padded to 16 bytes (fn 0x3314 feeds exactly 16 bytes)."""
    b = pw.encode("latin-1")[:16]
    return b + b"\x00" * (16 - len(b))


def X_of(pw: str) -> bytes:
    return hashlib.sha256(pw16(pw) + SALT).digest()


def Y_of(pw: str) -> bytes:
    return hashlib.sha256(X_of(pw) + SALT).digest()


def firmware_X(pw: str) -> bytes:
    """Execute the REAL 2.27.0 pw_4 fn 0x1BB4 (SHA256(in[16]||salt)) under
    unicorn — the same instruction path CF1B's verify session uses."""
    import struct
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UcError
    from unicorn.x86_const import (
        UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
        UC_X86_REG_R9, UC_X86_REG_RAX,
    )
    SENTINEL = 0x900000
    STACK = 0x100000
    HEAP = 0x200000
    d = open(MOD_227, "rb").read()
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", d, e_lfanew + 20)[0]
    so = e_lfanew + 24 + optsz
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, 0x100000)
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(HEAP, 0x10000)
    for i in range(nsec):
        off = so + i * 40
        vsz, va, rsz, ro = struct.unpack_from("<IIII", d, off + 8)
        uc.mem_write(va, d[ro:ro + rsz])
    uc.mem_write(HEAP, pw16(pw))
    uc.mem_write(HEAP + 0x40, b"\x00" * 8)         # &outlen
    sp = STACK + 0x10000 - 0x200
    uc.mem_write(sp, struct.pack("<Q", SENTINEL))
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RCX, HEAP)             # in
    uc.reg_write(UC_X86_REG_RDX, 0x10)             # len (exactly like 0x3314)
    uc.reg_write(UC_X86_REG_R8, HEAP + 0x20)       # out (32 B)
    uc.reg_write(UC_X86_REG_R9, HEAP + 0x40)       # &outlen
    uc.emu_start(FN_1BB4, SENTINEL, timeout=0, count=5_000_000)
    return bytes(uc.mem_read(HEAP + 0x20, 32))


def selftest():
    ok = True
    print("== Python X/Y vs REAL firmware fn 0x1BB4 (2.27.0 pw_4) ==")
    for pw in ("", "A", "shzNyjGRzRN2LLzL", "PaSsWoRd123!?", "x" * 16):
        fx = firmware_X(pw)
        px = X_of(pw)
        match = fx == px
        ok &= match
        print(f"  pw={pw!r:20s} X={px.hex()[:24]}… "
              f"{'FIRMWARE-MATCH' if match else 'MISMATCH fw=' + fx.hex()[:24]}")
    # sanity of the acceptance chain
    x, y = X_of("test"), Y_of("test")
    ok &= y == hashlib.sha256(x + SALT).digest()
    print("  Y = SHA256(X||salt) chain:", "OK" if ok else "FAIL")
    print("RESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def grind(r_hex: str, charset: str, maxlen: int):
    R = bytes.fromhex(r_hex)
    if len(R) != 32:
        print("R must be 32 bytes (64 hex chars)")
        return 1
    print(f"grinding: charset={len(charset)} chars, maxlen={maxlen}, "
          f"R={R.hex()}")
    space = 0
    for n in range(0, maxlen + 1):
        for tup in itertools.product(charset, repeat=n):
            pw = "".join(tup)
            space += 1
            if Y_of(pw) == R:
                print(f"FOUND: password = {pw!r}")
                return 0
        print(f"  len {n}: exhausted ({space} candidates)")
    print("not found in the given space")
    return 1


def main():
    args = sys.argv[1:]
    if not args or args[0] == "--selftest":
        return selftest()
    if args[0] == "--pw":
        pw = args[1]
        print(f"pw   = {pw!r}")
        print(f"pw16 = {pw16(pw).hex()}")
        print(f"X    = SHA256(pw16||salt) = {X_of(pw).hex()}")
        print(f"Y    = SHA256(X||salt)    = {Y_of(pw).hex()}")
        print("(the BIOS accepts the password iff the EC's R == Y)")
        return 0
    if args[0] == "--grind":
        r_hex = args[args.index("--R") + 1]
        charset = args[args.index("--charset") + 1] if "--charset" in args \
            else "abcdefghijklmnopqrstuvwxyz0123456789"
        maxlen = int(args[args.index("--maxlen") + 1]) if "--maxlen" in args \
            else 5
        return grind(r_hex, charset, maxlen)
    print(__doc__)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
