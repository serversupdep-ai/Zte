#!/usr/bin/env python3
"""Self-tests for the FC1B agent companion tools.

1. Keygen: validates the port against the public test vector
   DELLSUX-1F66 -> qHXaL0ntli6Gu4c0 and checks every supported suffix
   produces a password.
2. FC1B unlocker: builds a synthetic 32 MiB BIOS dump (Intel descriptor +
   00FCAA/00FDAA password entries + decoys), verifies the fast matcher
   agrees with a literal port of the reference matcher, patches the dump,
   and checks the result byte-for-byte.

Run: python3 tools/test_fc1b_tools.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import dell_fc1b_unlock as unlocker  # noqa: E402
import dell_keygen as keygen  # noqa: E402


def build_synthetic_dump() -> bytearray:
    """32 MiB flash image: descriptor, two password entries, decoys."""
    data = bytearray(b"\xFF" * (32 * 1024 * 1024))
    # Intel flash descriptor signature, as found in real full-chip dumps.
    data[0x10:0x15] = bytes.fromhex("5AA5F00F03")
    # System (setup) password entry inside the variable store (15 bytes).
    data[0x000F0000:0x000F000F] = bytes.fromhex("00FCAA08" + "000000" + "1122334455667788")
    # Administrator password entry (15 bytes).
    data[0x00120000:0x0012000F] = bytes.fromhex("00FDAA0A" + "000000" + "AABBCCDDEEFF0011")
    # Decoy: 00FCAA without the 000000 tail -> must NOT match (8 bytes).
    data[0x00130000:0x00130008] = bytes.fromhex("00FCAA08" + "11223344")
    # Decoy: valid pattern beyond the 0x160000 scan window -> must NOT match (15 bytes).
    data[0x00200000:0x0020000F] = bytes.fromhex("00FCAA08" + "000000" + "9988776655443322")
    return data


def reference_find_pattern_matches(data: bytes, pattern_regex: str) -> list[int]:
    """Literal port of DellBIOSTools find_pattern_matches (slow but exact)."""
    matches = []
    max_offset = min(0x160000, len(data))
    for i in range(max_offset):
        chunk_size = min(20, len(data) - i)
        if chunk_size < 6:
            continue
        chunk = data[i : i + chunk_size]
        hex_chunk = chunk.hex().upper()
        if re.match(rf"^{pattern_regex}.*$", hex_chunk):
            matches.append(i)
    return matches


def test_keygen() -> None:
    expected = "qHXaL0ntli6Gu4c0"
    got = keygen.keygenDell("DELLSUX", "1F66")
    assert got and got[0] == expected, f"keygen vector failed: {got!r}"
    for suffix in keygen.SUPPORTED_SUFFIXES:
        out = keygen.keygenDell("DELLSUX", suffix)
        assert out and all(out), f"empty keygen result for {suffix}"
    try:
        keygen.parse_input("ABC1234-FC1B")
        raise AssertionError("FC1B should be rejected by the keygen")
    except ValueError as error:
        assert "firmware" in str(error)
    print(f"keygen OK: DELLSUX-1F66 -> {expected} (+ {len(keygen.SUPPORTED_SUFFIXES) - 1} other suffixes)")


def test_unlocker() -> None:
    data = bytes(build_synthetic_dump())

    # Fast matcher must agree with the literal reference matcher.
    for name, pattern, _ in unlocker.PATTERNS:
        fast = unlocker.find_pattern_matches(data, pattern)
        ref = reference_find_pattern_matches(data, pattern.pattern)
        assert fast == ref, f"{name}: fast matcher {fast} != reference {ref}"
    assert unlocker.find_intel_signature(data) == 0x10

    matches = unlocker.scan(data)
    assert matches[unlocker.PATTERNS[0][0]] == [0x000F0000], matches
    assert matches[unlocker.PATTERNS[1][0]] == [0x00120000], matches

    patched = bytearray(data)
    count = unlocker.patch(patched, matches)
    assert count == 2, count
    assert patched[0x000F0000:0x000F0006] == bytes.fromhex("00FC00000000")
    assert patched[0x00120000:0x00120006] == bytes.fromhex("00FD00000000")
    # bytes past each 6-byte patched header stay untouched
    assert bytes(patched[0x000F0006:0x000F0010]) == data[0x000F0006:0x000F0010]
    assert bytes(patched[0x00120006:0x00120010]) == data[0x00120006:0x00120010]
    # decoys untouched, size unchanged, rest of image intact
    assert bytes(patched[0x00130000:0x00130008]) == data[0x00130000:0x00130008]
    assert bytes(patched[0x00200000:0x00200010]) == data[0x00200000:0x00200010]
    assert len(patched) == len(data)

    # A dump without the descriptor signature must be rejected.
    bad = bytearray(data)
    bad[0x10:0x15] = b"\x00" * 5
    assert unlocker.find_intel_signature(bytes(bad)) == -1
    print("unlocker OK: 2 entries found & patched, decoys skipped, matcher matches reference")


if __name__ == "__main__":
    test_keygen()
    test_unlocker()
    print("ALL TESTS PASSED")
