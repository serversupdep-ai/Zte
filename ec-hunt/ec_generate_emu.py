#!/usr/bin/env python3
"""ec_generate_emu.py — offline CF1B keygen completion harness.

Runs the EC's type-6 GENERATE transform from a PLAINTEXT EC firmware image
(the HIT artifact ec_hunt.py hunts for) under a Cortex-M emulator, for an
arbitrary (service tag, family) pair — producing the standalone keygen the
campaign wants: tag+suffix in -> master password out, no machine.

Why this works only with a HIT file: the EC computes
    master = f(tag, family_byte, per-build secret)
inside its internal firmware. Every public EC payload is AES-sealed
(per-build key fused in silicon), so offline generation is impossible
until a decrypted EC-internal dump ("EC程序", RT809H direct-EC read)
appears — exactly what the hunt watches for.

Pipeline once ec-hunt/HIT-ALERT.md exists:
  1. quarantine file -> locate the GENERATE handler:
     family-list window (>=3 of 1B58/9ABE/3FE2/CF1B/8FC8 as u16),
     salt 8dfc7b25 / SHA-256 K-table nearby, mailbox 0x910/0x911 access.
  2. load image into unicorn ARM (Thumb-2), map SRAM + mailbox shims.
  3. drive the mailbox handler with the §11.2 wire sequence:
       open {0x21,0x00,0x03,0x06} -> send tag -> send family LSB -> recv 32B
  4. resp[0:16] = master (CF1B verbatim; 8FC8 = alphabet72[(r[i]+r[i+16])%72]).
  5. cross-check against dell_cf1b_master readouts from validation machines
     (VALIDATION-LOG.md) — byte match => keygen complete.

Usage:
  python3 ec_generate_emu.py <plaintext_ec_image.bin> -t CVZKKD3 -f CF1B
"""
import argparse
import struct
import sys

FAMILIES = {"1B58": 0x1B58, "9ABE": 0x9ABE, "3FE2": 0x3FE2, "CF1B": 0xCF1B, "8FC8": 0x8FC8}
ASCII72 = b"012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"


def locate_generate_engine(img: bytes) -> dict:
    """Score-based localization of the GENERATE handler region (step 1)."""
    fam_hits = []
    for f in FAMILIES.values():
        fb = struct.pack("<H", f)
        idx = 0
        while True:
            i = img.find(fb, idx)
            if i < 0:
                break
            fam_hits.append((i, f))
            idx = i + 2
    if not fam_hits:
        return {"found": False, "reason": "no family u16 immediates"}
    fam_hits.sort()
    # densest 256-byte cluster of distinct families
    best, best_w = None, 0
    for i, (off, _) in enumerate(fam_hits):
        window = [f for (o, f) in fam_hits[i:] if o - off <= 256]
        w = len(set(window))
        if w > best_w:
            best, best_w = (off, window), w
    off, window = best
    region = img[max(0, off - 0x800): off + 0x800]
    return {
        "found": best_w >= 3,
        "offset": hex(off), "families_in_window": [hex(f) for f in sorted(set(window))],
        "salt_nearby": bytes.fromhex("8dfc7b25") in region or bytes.fromhex("257bfc8d") in region,
        "sha256_ktable_nearby": bytes.fromhex("d76aa478") in region,
    }


def generate_master(img_path: str, tag: str, family: int) -> str:
    """Steps 2-4: emulate. Requires a HIT image + unicorn; raises with a clear
    message if the image is not a plaintext GENERATE engine."""
    try:
        with open(img_path, "rb") as f:
            img = f.read()
    except OSError as e:
        sys.exit(f"cannot read {img_path}: {e}")
    loc = locate_generate_engine(img)
    print(f"[locate] {loc}")
    if not loc.get("found"):
        sys.exit("not a GENERATE-engine image (family list not found) — "
                 "this harness needs a HIT file from ec_hunt.py")
    try:
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS
        from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_PC
    except ImportError:
        sys.exit("pip install unicorn capstone  (emulator not installed)")
    # Cortex-M memory map: flash at 0, SRAM at 0x20000000
    BASE_FLASH, BASE_SRAM = 0x00000000, 0x20000000
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    mu.mem_map(BASE_FLASH, max(len(img), 0x20000))
    mu.mem_map(BASE_SRAM, 0x10000)
    mu.mem_write(BASE_FLASH, img)
    mu.reg_write(UC_ARM_REG_SP, BASE_SRAM + 0x8000)
    # --- wiring point: mailbox handler discovery + drive sequence ---
    # The handler entry is derived from the vector table / dispatch tables
    # located in step 1; drive with {0x21,0x00,0x03,0x06} + tag + family LSB.
    # Filled in against the first real HIT image (validation: VALIDATION-LOG
    # readouts must match byte-for-byte before the keygen is declared done).
    raise SystemExit(
        "engine located — mailbox-driver wiring pending the first real HIT "
        "image; validate against a dell_cf1b_master readout from "
        "VALIDATION-LOG.md once acquired")


def render(family: int, resp: bytes) -> str:
    if family == 0x8FC8:
        return bytes(ASCII72[(resp[i] + resp[i + 16]) % 72] for i in range(16)).decode()
    return resp[:16].decode("latin1")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("-t", "--tag", default="CVZKKD3")
    ap.add_argument("-f", "--family", default="CF1B", choices=list(FAMILIES))
    a = ap.parse_args()
    print(f"master: {generate_master(a.image, a.tag, FAMILIES[a.family])}")
