#!/usr/bin/env python3
"""extract_ec_payloads.py — pull PHCM (EC firmware) payloads out of a Dell
BIOS package (.exe) or .rcv image and save them for analysis/emulation.

Usage: python3 extract_ec_payloads.py <package.exe|image.bin> <outdir> [tag]

Walks the Dell PFS structure (via uefi_firmware.pfs.PFSFile, with the
DellUpdateBinary locate from extract_pw_modules.find_dub), recursively
including nested PFS.HDR sections, collects every section whose data starts
with the PHCM magic, dedupes, and writes:

    <outdir>/<tag>_ec_<n>_<size>.bin

Exit code 0 always if at least one payload was written.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from uefi_firmware.pfs import PFSFile          # noqa: E402
from extract_pw_modules import find_dub        # noqa: E402


def walk_pfs(data, found):
    """recursively collect PHCM section data blobs"""
    if data[:8] == b"PFS.HDR.":
        try:
            pfs = PFSFile(data)
            pfs.process()
        except Exception:
            return
        for s in pfs.sections:
            try:
                walk_pfs(s.section_data, found)
            except Exception:
                pass
    elif data[:4] == b"PHCM":
        found.append(data)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    pkg, outdir = sys.argv[1], sys.argv[2]
    tag = sys.argv[3] if len(sys.argv) > 3 else os.path.splitext(
        os.path.basename(pkg))[0].replace(" ", "_")
    data = open(pkg, "rb").read()
    dub = find_dub(data)
    if not dub:
        print(f"{pkg}: no Dell PFS found")
        return 1
    found = []
    walk_pfs(dub, found)
    # also try the raw image in case it IS the pfs
    if not found and data[:8] == b"PFS.HDR.":
        walk_pfs(data, found)
    # dedupe by hash
    seen = {}
    for blob in found:
        seen[hashlib.sha256(blob).hexdigest()] = blob
    os.makedirs(outdir, exist_ok=True)
    n = 0
    for h, blob in sorted(seen.items(), key=lambda kv: len(kv[1])):
        n += 1
        fn = os.path.join(outdir, f"{tag}_ec_{n}_{len(blob)}.bin")
        open(fn, "wb").write(blob)
        print(f"wrote {fn} (sha256 {h[:16]}...)")
    print(f"{n} unique PHCM payload(s) extracted")
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
