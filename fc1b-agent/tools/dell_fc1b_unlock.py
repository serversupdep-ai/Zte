#!/usr/bin/env python3
"""Dell FC1B / CF1B / 8FC8 BIOS dump password unlocker.

Dell machines that show a `-FC1B`, `-CF1B` or `-8FC8` suffix on the BIOS
password lock screen verify the password inside the firmware, so no
service-tag keygen exists for them. This tool implements the standard
recovery route: patch the BIOS password entries out of a full SPI flash
dump, so the lock is cleared when the dump is flashed back.

What it does
------------
1. Verifies the Intel flash descriptor signature (5A A5 F0 0F 03) within
   the first 4096 bytes - proof that the dump is a full-chip image.
2. Scans the first 0x160000 bytes for the two password entries in the
   BIOS variable store:
     - system/setup password entry:  00 FC AA <len 1-2 bytes> 00 00 00 <hash...>
     - administrator password entry: 00 FD AA <len 1-2 bytes> 00 00 00 <hash...>
3. Zeroes each matched entry header (first 6 bytes):
     - 00 FC AA ... -> 00 FC 00 00 00 00
     - 00 FD AA ... -> 00 FD 00 00 00 00
4. Writes the patched image next to the input as patched_<name>.bin.

Usage
-----
    python3 dell_fc1b_unlock.py dump.bin             # scan + patch
    python3 dell_fc1b_unlock.py dump.bin --scan-only # report matches only
    python3 dell_fc1b_unlock.py dump.bin --output patched.bin

After flashing the patched image, the machine will warn
"The Service Tag has not been programmed"; enter the service tag and the
machine reboots with the BIOS password cleared.

Logic ported from the public "Dell BIOS Unlocker 8FC8/CF1B"
(github.com/chromebreakerdev/DellBIOSTools).

Only use this on machines you own or are authorized to service.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

INTEL_SIGNATURE = bytes.fromhex("5AA5F00F03")
INTEL_SEARCH_LIMIT = 0x1000        # signature must sit within the first 4 KiB
SCAN_LIMIT = 0x160000              # password entries are searched in the first ~1.4 MiB
WINDOW = 20                        # reference tool scans 20-byte windows at each offset

# (name, hex-string regex, replacement bytes)
PATTERNS = [
    (
        "system (setup) password entry 00FCAA",
        re.compile(r"00FCAA[0-9A-F]{2,4}000000[0-9A-F]{2,}"),
        bytes.fromhex("00FC00"),
    ),
    (
        "administrator password entry 00FDAA",
        re.compile(r"00FDAA[0-9A-F]{2,4}000000[0-9A-F]{2,}"),
        bytes.fromhex("00FD00"),
    ),
]


def find_intel_signature(data: bytes, signature: bytes = INTEL_SIGNATURE) -> int:
    """Offset of the Intel flash descriptor signature, or -1."""
    limit = min(INTEL_SEARCH_LIMIT, max(0, len(data) - len(signature)))
    return data.find(signature, 0, limit + len(signature)) if limit > 0 else -1


def find_pattern_matches(data: bytes, pattern: re.Pattern) -> list[int]:
    """All byte offsets whose 20-byte window matches the pattern.

    Equivalent to the reference implementation (regex on the hex string of
    data[i:i+20] for every i < SCAN_LIMIT) but computed in one pass over
    the hex string with overlapping lookahead matches.
    """
    max_offset = min(SCAN_LIMIT, len(data))
    region = data[: max_offset + WINDOW]
    hex_region = region.hex().upper()
    offsets: list[int] = []
    for match in re.finditer(rf"(?=({pattern.pattern}))", hex_region):
        offset = match.start(1) // 2
        if offset < max_offset:
            offsets.append(offset)
    return offsets


def scan(data: bytes) -> dict[str, list[int]]:
    """Map each pattern name to its matched offsets."""
    return {name: find_pattern_matches(data, pattern) for name, pattern, _ in PATTERNS}


def patch(data: bytearray, matches: dict[str, list[int]]) -> int:
    """Zero each matched entry header; returns number of patched offsets."""
    patched = 0
    for (name, _, replacement), offsets in zip(PATTERNS, matches.values()):
        for offset in offsets:
            data[offset : offset + 6] = replacement + bytes(6 - len(replacement))
            patched += 1
    return patched


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Scan and patch a Dell FC1B/CF1B/8FC8 BIOS dump to clear the BIOS password.",
    )
    parser.add_argument("dump", help="full SPI flash dump (.bin) of the locked machine")
    parser.add_argument("--output", help="output path (default: patched_<name> next to input)")
    parser.add_argument(
        "--scan-only", action="store_true", help="only report matches; do not write a patched file"
    )
    args = parser.parse_args(argv[1:])

    source = Path(args.dump)
    if not source.is_file():
        print(f"error: no such file: {source}", file=sys.stderr)
        return 1
    data = bytearray(source.read_bytes())
    print(f"loaded {source.name}: {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MiB)")

    sig_offset = find_intel_signature(bytes(data))
    if sig_offset < 0:
        print(
            "error: Intel flash descriptor signature (5A A5 F0 0F 03) not found in the first "
            "4096 bytes. This does not look like a full-chip dump; re-read the whole flash "
            "chip with a programmer and try again.",
            file=sys.stderr,
        )
        return 1
    print(f"Intel flash descriptor signature found at offset 0x{sig_offset:X}")

    matches = scan(bytes(data))
    total = sum(len(v) for v in matches.values())
    for name, offsets in matches.items():
        for offset in offsets:
            print(f"match: {name} at offset 0x{offset:X}")
    if total == 0:
        print(
            "warning: no 00FCAA/00FDAA password entries found in the first 0x160000 bytes. "
            "The dump may use a different layout; nothing was changed."
        )
        return 2

    if args.scan_only:
        print(f"scan complete: {total} password entr{'y' if total == 1 else 'ies'} found (no file written).")
        return 0

    patched = patch(data, matches)
    output = Path(args.output) if args.output else source.with_name(f"patched_{source.name}")
    output.write_bytes(bytes(data))
    assert len(data) == source.stat().st_size
    print(f"patched {patched} password ent{'y' if patched == 1 else 'ies'}; wrote {output} ({len(data)} bytes)")
    print(
        "next: flash the patched image back with your programmer, boot the machine, enter the "
        "service tag when warned 'The Service Tag has not been programmed', and the machine "
        "reboots with the BIOS password cleared. Keep the original dump as a backup."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
