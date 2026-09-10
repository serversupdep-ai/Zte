#!/usr/bin/env python3
"""build_salts_db.py — turn collected real Dell firmware data into source code.

Scans every password module under bios-analysis/collected/ (and the original
pwmods/ reference set), extracts the challenge-construction facts, and
GENERATES bios-analysis/dell_salts_db.py — a committed, importable database:

    from dell_salts_db import DB, challenge_hash

Extracted per module:
  - OpenSSL SHA-256 build string (primitive provenance)
  - the static EC-path salt(s): 4-byte constants fed to the hash via
    `lea rdx,[rip+X] ... mov r8d,4 ; call sha_update` (REPORT §13)
  - EC-routed family membership lists (u16 lists near the alphabet marker)
  - platform-type GUID tables (when present)

Usage:  python3 build_salts_db.py [dirs...]      # default: collected/ + pwmods/
"""
import glob
import hashlib
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

KNOWN_FAMILIES = {0x8FC8, 0xCF1B, 0x1B58, 0x9ABE, 0x3FE2, 0xE7A8, 0xBF97,
                  0x6FF1, 0x1F66, 0x1D3B, 0x2A7B}
FAMILY_NAMES = {0x8FC8: "8FC8", 0xCF1B: "CF1B", 0x1B58: "1B58",
                0x9ABE: "9ABE", 0x3FE2: "3FE2", 0xE7A8: "E7A8",
                0xBF97: "BF97", 0x6FF1: "6FF1", 0x1F66: "1F66",
                0x1D3B: "1D3B", 0x2A7B: "2A7B"}


def img_of(path):
    """Map a .efi/.bin file to its PE memory image (or raw bytes)."""
    data = open(path, "rb").read()
    mz = data.find(b"MZ")
    if mz < 0:
        return data, data
    try:
        import pefile
        pe = pefile.PE(data=data[mz:], fast_load=True)
        return data[mz:], bytes(pe.get_memory_mapped_image())
    except Exception:
        return data[mz:], data[mz:]


def find_salts(img):
    """Find 4-byte salt constants at sha-update sites.

    Pattern: `lea rdx,[rip+rel32]` ... within ~0x30 bytes ... `mov r8d,4`
    (41 B8 04 00 00 00) followed by a call (E8/E9 or FF) — the wrapper's
    second update call (salt), per REPORT §13 fn 0x1bb4/0x1b28.
    """
    salts = set()
    for m in re.finditer(re.escape(bytes.fromhex("41b804000000")), img):
        i = m.start()
        # walk back to the nearest lea rdx,[rip+X]
        for j in range(i - 1, max(0, i - 0x38), -1):
            if img[j:j + 3] == bytes.fromhex("488D15"):        # lea rdx,[rip+rel32]
                rel = struct.unpack_from("<i", img, j + 3)[0]
                tgt = j + 7 + rel
                if 0 <= tgt < len(img) - 4:
                    salts.add(bytes(img[tgt:tgt + 4]))
                break
    return salts


def find_member_lists(img):
    """Find EC-routed family lists: u16 runs of known families + FFFF end."""
    out = []
    i = 0
    n = len(img)
    while i < n - 2:
        w = struct.unpack_from("<H", img, i)[0]
        if w in KNOWN_FAMILIES:
            j, fams = i, []
            while j < n - 2:
                v = struct.unpack_from("<H", img, j)[0]
                if v == 0xFFFF:
                    if len(fams) >= 1:
                        out.append((i, fams))
                    break
                if v not in KNOWN_FAMILIES:
                    break
                fams.append(v)
                j += 2
            i = j + 2
        else:
            i += 2
    # dedupe
    seen, res = set(), []
    for off, fams in out:
        key = tuple(fams)
        if key not in seen:
            seen.add(key)
            res.append((off, fams))
    return res


def find_platform_guids(img):
    """Find the 7-entry platform-type GUID table (bb52d484... anchor)."""
    anchor = bytes.fromhex("84d452bb3fdca14f")   # type-0 GUID first 8 bytes LE
    i = img.find(anchor)
    if i < 0:
        return []
    guids = []
    for t in range(7):
        b = img[i + 16 * t:i + 16 * t + 16]
        d1, d2, d3 = struct.unpack_from("<IHH", b, 0)
        guids.append(f"{d1:08x}-{d2:04x}-{d3:04x}-{b[8]:02x}{b[9]:02x}-{b[10:].hex()}")
    return guids


def scan_module(path):
    raw, img = img_of(path)
    entry = {"file": path.replace("\\", "/"), "size": os.path.getsize(path)}
    m = re.search(rb"SHA-256 part of OpenSSL ([0-9A-Za-z. ]+)", img)
    entry["sha256_build"] = m.group(1).decode("latin-1").strip() if m else None
    entry["salts"] = sorted(s.hex() for s in find_salts(img))
    lists = find_member_lists(img)
    entry["family_lists"] = [[FAMILY_NAMES.get(f, f"{f:04X}") for f in fams]
                             for _off, fams in lists]
    guids = find_platform_guids(img)
    entry["platform_types"] = guids if guids else None
    entry["alphabet"] = True if img.find(b"0Q2drGk99") >= 0 else False
    return entry


def main():
    roots = sys.argv[1:]
    if not roots:
        roots = [os.path.join(HERE, "collected"),
                 os.path.join(HERE, "optiplex3090", "pwmods")]
    modules = []
    for root in roots:
        for pat in ("**/*.efi", "**/pw_*.bin"):
            modules += glob.glob(os.path.join(root, pat), recursive=True)
    db = []
    seen_files = set()
    for p in sorted(set(modules)):
        key = os.path.basename(p)
        if key in seen_files:
            continue
        try:
            e = scan_module(p)
        except Exception as ex:
            print(f"  ! {p}: {ex}", file=sys.stderr)
            continue
        seen_files.add(key)
        # keep only real password modules: alphabet marker or family lists
        if not (e["alphabet"] or e["family_lists"]):
            continue
        if not e.get("sha256_build") and not e["alphabet"]:
            e["salts"] = []          # nothing confirms this is a pw module
        db.append(e)
        print(f"  {p}: salts={e['salts']} lists={e['family_lists']} "
              f"alpha={e['alphabet']} sha={e['sha256_build']}")

    out = os.path.join(HERE, "dell_salts_db.py")
    with open(out, "w") as f:
        f.write('"""dell_salts_db.py — GENERATED by build_salts_db.py\n'
                'Facts extracted from real Dell firmware data collected from\n'
                'the internet (relay/catalog.txt -> bios-analysis/collected/),\n'
                'plus the original reference modules. Do not hand-edit;\n'
                'regenerate with: python3 build_salts_db.py\n'
                'See REPORT.md §13 for the construction this database feeds.\n'
                '"""\n\n'
                'import hashlib\n\n'
                'DB = ')
        f.write(repr(db).replace("}, {", "},\n      {"))
        f.write('\n\n\n'
                'def challenge_hash(data, salt=bytes.fromhex("8dfc7b25")):\n'
                '    """SHA256(data || salt) — the EC-path challenge primitive."""\n'
                '    return hashlib.sha256(bytes(data) + bytes(salt)).digest()\n'
                '\n\n'
                'def all_salts():\n'
                '    """Every distinct salt seen across all real modules."""\n'
                '    s = set()\n'
                '    for e in DB:\n'
                '        s.update(e.get("salts", []))\n'
                '    return sorted(s)\n'
                '\n\n'
                'if __name__ == "__main__":\n'
                '    print(f"{len(DB)} modules in DB")\n'
                '    print("distinct salts:", all_salts())\n')
    print(f"\nwrote {out} ({len(db)} modules)")


if __name__ == "__main__":
    main()
