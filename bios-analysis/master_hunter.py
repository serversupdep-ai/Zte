#!/usr/bin/env python3
"""master_hunter.py — the unified hunt tool (driven by MISSION_PROMPT.md).

Commands:
  status                print the solution matrix (the scoreboard)
  scan FILE [--dvar]    full artifact recognition suite on one file
  watch [--write]       fresh venue-sweep fetchlist entries (_rN tags)
  leads                 the ranked live-leads list

stdlib-only (dellpwn_port imported for DVAR scanning when present).
"""
import sys, os, re, hashlib, struct

# ---------------------------------------------------------------- signatures
INV_SBOX = bytes.fromhex(
 "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
 "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
 "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
 "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
 "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
 "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
 "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
 "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d")
FWD_SBOX = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0")
T0_LE    = bytes.fromhex("c66363a5")

def find_all(data, sig, limit=6):
    out, pos = [], 0
    while len(out) < limit:
        i = data.find(sig, pos)
        if i < 0: break
        out.append(i); pos = i + 1
    return out

def validated_phcm(data):
    out = []
    for m in re.finditer(re.escape(b"PHCM"), data):
        off = m.start()
        if off + 0xc0 > len(data): continue
        n = struct.unpack_from("<I", data, off+0x10)[0]
        hsize = struct.unpack_from("<I", data, off+0x14)[0]
        if hsize == 0xc0 and 0 < n < 0x10000 and data[off+0x40:off+0x50] != b"\xff"*16:
            out.append((off, n, data[off+4:off+8].hex()))
    return out

def sivb_blocks(data):
    out = []
    for i in find_all(data, b"SIVB", limit=32):
        if i >= 4 and i + 5552 <= len(data):
            if struct.unpack_from("<H", data, i-4)[0] == 0x20:
                nontrivial = sum(1 for b in data[i+4:i+5552] if b not in (0, 0xFF))
                out.append((i-4, nontrivial))
    return out

def ec_bundle_chains(data):
    out = []
    for off in range(0, len(data) - 32, 4):
        a, sz1, addr, sz2 = struct.unpack_from("<IIII", data, off)
        if a == 7 and 0 < sz1 < 0x20000 and 0x80400000 <= addr < 0x80420000 and 0 < sz2 < 0x20000:
            out.append((off, sz1, addr, sz2))
    return out

def npcx_vectors(data, limit=4):
    out = []
    for i in range(0, min(len(data) - 0x100, 0x400000), 4):
        sp = struct.unpack_from("<I", data, i)[0]
        if 0x20000000 <= sp <= 0x20030000:
            ent = struct.unpack_from("<I", data, i+4)[0]
            if ent & 1 and 0x100 < ent < 0x20000:
                ok = sum(1 for j in range(2, 10)
                         if (struct.unpack_from("<I", data, i+4*j)[0] & 1)
                         and struct.unpack_from("<I", data, i+4*j)[0] < 0x20000)
                if ok >= 3:
                    out.append((i, sp, ent))
                    if len(out) >= limit: break
    return out

# ---------------------------------------------------------------- scan
def scan(path, do_dvar=False):
    data = open(path, "rb").read()
    name = os.path.basename(path)
    print(f"=== master_hunter scan: {name} ({len(data):,} B, sha256 {hashlib.sha256(data).hexdigest()[:16]}…)")
    findings = []

    inv = find_all(data, INV_SBOX[:16])
    if inv:
        findings.append(f"*** AES INVERSE S-box @ {[hex(x) for x in inv]} — DECRYPT-ONLY ENGINE PRESENT (§11.16)")
    fwd = find_all(data, FWD_SBOX)
    if fwd:
        findings.append(f"    AES forward S-box @ {[hex(x) for x in fwd]}")
    if find_all(data, T0_LE):
        findings.append("    AES T-table @ ...")
    for off, n, ver in validated_phcm(data):
        findings.append(f"    PHCM container @0x{off:x}: n={n:#x} ver={ver} (sealed store)")
    for off, nt in sivb_blocks(data):
        findings.append(f"    SIVB vault @0x{off:x}: {nt} non-trivial bytes "
                        f"({'HAS DATA — clear-sivb applies' if nt > 10 else 'empty'})")
    chains = ec_bundle_chains(data)
    if chains:
        findings.append(f"*** NPCX EC bundle record chain @ {[hex(c[0]) for c in chains[:4]]} "
                        f"(factory EC staging — §11.16; check for unstaged 0x80418020 key area)")
    for i, sp, ent in npcx_vectors(data):
        findings.append(f"    NPCX vector table @0x{i:x}: SP={sp:#010x} entry={ent:#010x}")
    for sig, label in ((b"$FPT", "$FPT (CSME)"), (b"DVAR", "DVAR store"),):
        hits = find_all(data, sig, 4)
        if hits:
            findings.append(f"    {label} @ {[hex(h) for h in hits]}")

    if do_dvar:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            from dellpwn_port import scan_for_passwords
            seen_off = set()
            for r in find_all(data, b"DVAR", 8):
                for off, pw, key, part in scan_for_passwords(data, r, min(r+0x40000, len(data)), False):
                    if off in seen_off: continue
                    seen_off.add(off)
                    findings.append(f"*** DVAR PASSWORD @0x{off:x}: {pw!r} key=0x{key}")
        except ImportError:
            findings.append("    (dellpwn_port.py not importable — DVAR scan skipped)")

    if not findings:
        print("  no hunt signatures found (not a Dell firmware artifact?)")
    for f in findings:
        print("  " + f)
    engine = any(f.startswith("*** AES INVERSE") for f in findings)
    if engine:
        print("  VERDICT: engine-carrying artifact — deep-reverse per §11.16 immediately")
    return findings

# ---------------------------------------------------------------- status/leads/watch
MATRIX = """SOLUTION MATRIX — Dell BIOS master password by model class
  Legacy (E7A8 BF97 6FF1 1F66 1D3B 2A7B) : SOLVED — dell_master_keygen.py (offline, selftest PASS)
  EC-era  (CF1B 8FC8 9ABE 3FE2 1B58)     : UNLOCK AVAILABLE (Route A/B/C) — KEYGEN OPEN
    missing input: EC internal-flash dump for the build / unwrapped per-build key
    newest attack surface: encoded NPCX payload @0x7b59fc bundle + KEK @0x80418020 (§11.16)
"""

LEADS = """RANKED LIVE LEADS (full detail: agent/KEYGEN_HUNT_AGENT/05-live-leads.md)
 1. Dell factory/service firmware — full EC images (not sealed PHCM, not 0x6a60 regions)
 2. Nuvoton NPCX7 vendor SDK / firmware leaks (EC chip identified §11.16.3)
 3. GitHub monthly sweep — new tools (dellpwn found this way); code search: PHCM, 0x8040e000, dell ec dump
 4. Locked+patched dump pairs spanning a build's first boot (wrap-material diff)
 5. Issue #5 volunteer: live 3090 owner runs dell_cf1b_master-linux (validates candidates)
 6. Venue re-scan (monthly): t.me/s/biosarchive, vinafix 45618, badcaps 98981/3217350/85841,
    dr-bios 3090 threads, indiafix wayback, pkbiosfix — new dumps weekly
"""

SWEEP = """# === master_hunter watch sweep (auto) ===
PAGE|https://t.me/s/biosarchive|tgbiosarchive_watch
PAGE|https://vinafix.com/threads/45618/|vinafix_3090_45618_watch
PAGE|https://www.badcaps.net/forum/showthread.php?t=98981|badcaps_3090_98981_watch
PAGE|https://www.dr-bios.com/mht/Dell-OptiPlex-3090-212037-1/68894|drbios_3090_68894_watch
"""

def main():
    if len(sys.argv) < 2 or sys.argv[1] == "status":
        print(MATRIX)
    elif sys.argv[1] == "leads":
        print(LEADS)
    elif sys.argv[1] == "scan":
        if len(sys.argv) < 3:
            sys.exit("usage: master_hunter.py scan FILE [--dvar]")
        scan(sys.argv[2], "--dvar" in sys.argv)
    elif sys.argv[1] == "watch":
        if "--write" in sys.argv:
            fl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "relay", "fetchlist.txt")
            with open(fl, "a") as f:
                f.write(SWEEP)
            print(f"sweep appended to {os.path.abspath(fl)} — commit+push to trigger the relay")
        else:
            sys.stdout.write(SWEEP)
    else:
        sys.exit(__doc__)

if __name__ == "__main__":
    main()
