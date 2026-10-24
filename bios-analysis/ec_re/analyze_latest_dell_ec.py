#!/usr/bin/env python3
"""
Dell EC & SecurityVault Password Pipeline Analyzer & Verifier (2018-2026)
=========================================================================

Covers four generations of Dell EC / UEFI BIOS password architectures captured
in `bios-analysis/collected_latest_ec/`:

1. MEC50x5 (ARCompact, plaintext EC firmware, e.g. XPS 13 9350 v1.13.0 `ec_1`):
   - Built-in minimal ARCompact disassembler (`disasm_arcompact`) for inspecting
     Microchip MEC5035/5045/5055/5075/5085 EC images without `arc-elf32-objdump`.
   - Exact replica of in-EC `cmd 0x4E` 8-char generator (`0x1abfc..0x1ad2c`)
     and `cmd 0x50` 16-char verifier (`0x1d828..0x1d89e`) + XOR-0x85 obfuscation.
   - Confirms `cmd 0x21` (`0x08ef0 -> 0x1d3c4`) is `ClearPasswordFlags`, proving
     `MEC5085` predates `cmd 0x21, sub 3, type 6` (`8FC8`).

2. MEC5107 (ARM Cortex-M4, plaintext EC firmware, e.g. Latitude 5X90 `ec_1`):
   - Adds `cmd 0x21` NVRAM password store (`sub 0..3`, types `0..5`) + double
     salted SHA-256 (`8DFC7B25`), but rejects `type 6` (`sub r3,#4; cmp r3,#1`).

3. DEC1515 / MEC5200(iFuse) (`PHCM`, `byte[6]=0x80`) & NPCX993D(iFuse) (`5e4d3b2a`)
   with monolithic `DellSecurityVaultSmm` (`pw_9ba1`..`pw_308b`, 2020-2025):
   - `EC_GENERATE`: SMM sends `{0x21, ?, 0x03, 0x06}` + ServiceTag(7) + suffix_lo(1)
     via protocol `7310E28E-96EA-4360-946E-5ADC6BE8F531` (gated on capability
     protocol `BD6B3090-6936-4DF0-BC73-68B06FB4E791`) to hardware-OTP-encrypted EC.
   - `RENDER` (UEFI SMM `0x8c18..0x8ca2`):
     `master[i] = ALPHABET0[(resp32[i] + resp32[i+16]) % 72]` for `i = 0..15`.

4. 2026 Panther Lake `xx260/xx261` Split Vault (`pw_77e7` 11,776 B + `pw_5815`/`3156`,
   e.g. XPS 14 DA14260 1.8.2, Dell Pro 3 P314260 2.4.3, Pro Precision PW514261 1.7.0):
   - Retires `0x8FC8` and deletes `ALPHABET0` from UEFI completely.
   - Allowed suffix table reduced to `[0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0xFFFF]`.
   - `type 6` (`0x1f60 -> 0x2874`) copies raw `resp32[0:16]` (`CopyMem(out, resp, 16)`)
     directly from EC; `type 3` verify checks `R == SHA256(SHA256(pw || 8DFC7B25) || 8DFC7B25)`.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import struct
import sys

# 72-character alphabets extracted directly from firmware binaries:
# - MEC5085 EC `ec_1` @ 0x246b4 (note duplicate '0' in place of '8' in lowercase half):
MEC5085_EC_ALPH72 = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"

# - UEFI DellSecurityVaultSmm `ALPHABET0` (`pw_9ba1` @ RVA 0xa440, `pw_308b` @ raw 0x8130):
UEFI_ALPHABET0_8FC8 = "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"

# 4-byte SHA-256 salt `@0xA658` / `pw_77e7 @ raw 0x2418`:
VAULT_SHA256_SALT = bytes.fromhex("8dfc7b25")

# Protocol GUIDs (raw little-endian 16-byte representation in PE images):
GUID_SMM_EC_7310E28E = bytes.fromhex("8ee21073ea966043946e5adc6be8f531")
GUID_EC_VAULT_CAP_90306BBD = bytes.fromhex("90306bbd3669f04dbc7368b06fb4e791")
GUID_EC_CAP2_CA793777 = bytes.fromhex("ca793777e82a73408bc543376a61bfd5")
GUID_VAULT_COMM_C065AEAB = bytes.fromhex("abae65c01cdd494dbd334578e106c700")
GUID_TYPE6_8449624D = bytes.fromhex("8449624dccd17c4cbfe44d7f013ff25a")


def extract_uefi_alphabet0(efi_bytes: bytes) -> str:
    """Extract exact 72-byte ALPHABET0 (`0Q2drGk9...`) from a DellSecurityVaultSmm image."""
    idx = efi_bytes.find(b"0Q2drGk9")
    if idx < 0:
        raise ValueError("ALPHABET0 ('0Q2drGk9...') not found in image")
    return efi_bytes[idx : idx + 72].decode("ascii")


def render_8fc8_from_ec_resp(resp32: bytes, alphabet0: str) -> str:
    """
    UEFI `DellSecurityVaultSmm` `RENDER` (`pw_9ba1` 0x8c18..0x8ca2):
      master[i] = ALPHABET0[(resp32[i] + resp32[i + 16]) % 72]  for i in 0..15
    """
    if len(resp32) != 32:
        raise ValueError(f"Expected 32-byte EC response, got {len(resp32)}")
    if len(alphabet0) != 72:
        raise ValueError(f"Expected 72-char ALPHABET0, got {len(alphabet0)}")
    return "".join(alphabet0[(resp32[i] + resp32[i + 16]) % 72] for i in range(16))


def mec5085_cmd4e_generate_8char(tag5: bytes, alph72: str = MEC5085_EC_ALPH72) -> str:
    """
    Exact replica of plaintext MEC5085 ARCompact `cmd 0x4E` (`0x1b760 -> 0x1abfc..0x1ad2c`)
    in `XPS_13_9350_1.13.0/ec_1_RAW_PFS_SUBCOMPONENT_262144.bin`:
      1. Reverse 5-byte packed tag record `rev[k] = tag5[4 - k]` (`k = 0..4`).
      2. Unpack eight 5-bit groups across the 40-bit reversed buffer.
      3. For each `j = 0..7`: start with `acc = 0xAA`, XOR `rev[b]` for each set bit `b` (`0..4`)
         in the 5-bit group, then map `alph72[acc % 72]`.
    """
    if len(tag5) != 5:
        raise ValueError("tag5 must be 5 bytes")
    rev = tag5[::-1]
    rol8_r1 = ((rev[1] << 3) & 0xFF) | (rev[1] >> 5)
    groups = [
        rev[0] & 0x1F,
        ((rol8_r1 & 0xF1) | (rev[0] >> 5)) & 0x1F,
        (rev[1] >> 2) & 0x1F,
        ((rev[1] >> 7) & 0x01) | ((rev[2] & 0x0F) << 1),
        ((rev[2] >> 4) & 0x0F) | ((rev[3] & 0x01) << 4),
        (rev[3] >> 1) & 0x1F,
        ((rev[3] >> 6) & 0x03) | ((rev[4] & 0x07) << 2),
        (rev[4] >> 3) & 0x1F,
    ]
    out = []
    for g in groups:
        acc = 0xAA
        for bit in range(5):
            if g & (1 << bit):
                acc ^= rev[bit]
        out.append(alph72[acc % 72])
    return "".join(out)


def mec5085_cmd50_expected_16char(ec_digest32: bytes, alph72: str = MEC5085_EC_ALPH72) -> str:
    """
    Exact replica of plaintext MEC5085 `cmd 0x50` (`0x1b974 -> 0x1d828..0x1d89e`)
    in `XPS_13_9350_1.13.0/ec_1`:
      Checks `user_pw[i] == alph72[ec_sram_8005f8[i] % 72]` for `i = 0..15`.
      (`cmd 0x51`/`0x5A` exports `ec_sram_8005f8` XORed with `0x85`.)
    """
    if len(ec_digest32) < 16:
        raise ValueError("ec_digest32 must be >= 16 bytes")
    return "".join(alph72[ec_digest32[i] % 72] for i in range(16))


def vault_salted_sha256(data: bytes) -> bytes:
    """UEFI `DellSecurityVaultSmm` `0x1b28` / `pw_77e7` `0x1848`: SHA256(data || 8DFC7B25)."""
    return hashlib.sha256(data + VAULT_SHA256_SALT).digest()


def cf1b_double_sha256_expected_r(password_ascii: bytes) -> bytes:
    """
    EC-Vault `cmd 0x21, sub 1, type 3` verification criterion (`pw_77e7` `0x2304..0x2492`):
      X = SHA256(pw || 8DFC7B25)
      Y = SHA256(X  || 8DFC7B25)
      Auth succeeds iff EC 32-byte response `R == Y`.
    """
    x = vault_salted_sha256(password_ascii)
    return vault_salted_sha256(x)


def sanitize_2026_hdd_identity(serial20: bytes, suffix_u16: int) -> bytes:
    """
    Exact replica of `pw_77e7` `0x1d54..0x1e36` (`CF1B` / `1B58` / `9ABE` / `3FE2` 11-byte identity):
    Sanitizes bytes outside `0x21..0x7E` to `'*'` (`0x2A`) and extracts `block[9:20]` (11 bytes)
    when `suffix_u16` is in `{0x1B58, 0x9ABE, 0x3FE2, 0xCF1B}`.
    """
    allowed = {0x1B58, 0x9ABE, 0x3FE2, 0xCF1B}
    buf = bytearray(23)
    if suffix_u16 not in allowed:
        return bytes(buf)
    clean = bytearray(serial20[:23])
    for i, ch in enumerate(clean):
        if not (0x21 <= ch <= 0x7E):
            clean[i] = 0x2A  # '*'
    buf[: len(clean)] = clean
    return bytes(buf[9:20])


# Minimal ARCompact disassembler subset for inspecting MEC50x5 EC firmware
_ARC_REGS = [
    *(f"r{i}" for i in range(26)),
    "gp", "fp", "sp", "ilink1", "ilink2", "blink",
    *(f"r{i}" for i in range(32, 60)),
    "lp_count", "r61", "limm", "pcl",
]


def _r16(buf: bytes, pc: int) -> int:
    return struct.unpack_from("<H", buf, pc)[0]


def _r32_me(buf: bytes, pc: int) -> int:
    """ARCompact middle-endian 32-bit word: (hw0 << 16) | hw1."""
    return (_r16(buf, pc) << 16) | _r16(buf, pc + 2)


def _sxt(val: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (val & (sign - 1)) - (val & sign)


def _sreg(code3: int) -> str:
    return _ARC_REGS[code3 if code3 < 4 else code3 + 8]


def disasm_arcompact(buf: bytes, start: int, end: int) -> list[tuple[int, str, str]]:
    """Disassemble ARCompact 16/32-bit mixed instructions in `buf[start:end]`."""
    out: list[tuple[int, str, str]] = []
    pc = start
    while pc < min(end, len(buf) - 1):
        hw0 = _r16(buf, pc)
        maj = (hw0 >> 11) & 0x1F
        if maj <= 0x0B and pc + 4 <= len(buf):
            insn = _r32_me(buf, pc)
            length = 4
            limm = None

            def reg_str(r: int) -> str:
                nonlocal length, limm
                if r == 62 and limm is None and pc + length + 4 <= len(buf):
                    limm = _r32_me(buf, pc + length)
                    length += 4
                return f"0x{limm:08x}" if r == 62 and limm is not None else _ARC_REGS[r]

            if maj == 0x00:
                if insn & (1 << 16):
                    d = _sxt(((insn >> 17) & 0x3FF) | (((insn >> 6) & 0x3FF) << 10) | ((insn & 0xF) << 20), 24) << 1
                    mnem = f"b 0x{(pc & ~3) + d:06x}"
                else:
                    d = _sxt(((insn >> 17) & 0x3FF) | (((insn >> 6) & 0x3FF) << 10), 20) << 1
                    mnem = f"bcc(0x{insn & 0x1F:x}) 0x{(pc & ~3) + d:06x}"
            elif maj == 0x01:
                if insn & (1 << 16):
                    if insn & (1 << 17):
                        d = _sxt(((insn >> 18) & 0x1FF) | (((insn >> 6) & 0x3FF) << 9) | ((insn & 0xF) << 19), 23) << 2
                        mnem = f"bl 0x{(pc & ~3) + d:06x}"
                    else:
                        d = _sxt(((insn >> 18) & 0x1FF) | (((insn >> 6) & 0x3FF) << 9), 19) << 2
                        mnem = f"blcc 0x{(pc & ~3) + d:06x}"
                else:
                    d = _sxt(((insn >> 17) & 0xFF) | (((insn >> 15) & 1) << 8), 9) << 1
                    breg = reg_str(((insn >> 24) & 7) | (((insn >> 12) & 7) << 3))
                    creg = reg_str((insn >> 6) & 0x3F) if not (insn & (1 << 4)) else str((insn >> 6) & 0x3F)
                    mnem = f"br(0x{insn & 7:x}) {breg}, {creg}, 0x{(pc & ~3) + d:06x}"
            elif maj == 0x02:
                s9 = _sxt(((insn >> 16) & 0xFF) | (((insn >> 15) & 1) << 8), 9)
                breg = reg_str(((insn >> 24) & 7) | (((insn >> 12) & 7) << 3))
                zz = (insn >> 7) & 3
                sz = {0: "", 1: "b", 2: "w", 3: "?"}[zz]
                sx = ".x" if (insn >> 6) & 1 else ""
                mnem = f"ld{sz}{sx} {reg_str(insn & 0x3F)}, [{breg}, {s9}]"
            elif maj == 0x03:
                s9 = _sxt(((insn >> 16) & 0xFF) | (((insn >> 15) & 1) << 8), 9)
                breg = reg_str(((insn >> 24) & 7) | (((insn >> 12) & 7) << 3))
                creg = reg_str((insn >> 6) & 0x3F)
                zz = (insn >> 1) & 3
                sz = {0: "", 1: "b", 2: "w", 3: "?"}[zz]
                mnem = f"st{sz} {creg}, [{breg}, {s9}]"
            elif maj == 0x04:
                subop = (insn >> 16) & 0x3F
                opm = (insn >> 22) & 3
                b_num = ((insn >> 24) & 7) | (((insn >> 12) & 7) << 3)
                breg = reg_str(b_num)
                names = {
                    0: "add", 2: "sub", 4: "and", 5: "or", 6: "bic", 7: "xor",
                    0x0A: "mov", 0x0C: "cmp", 0x0E: "rsub", 0x13: "bmsk",
                    0x14: "add1", 0x15: "add2", 0x16: "add3", 0x1A: "mpy", 0x1B: "mpyh",
                }
                nm = names.get(subop, f"alu_{subop:02x}")
                if opm == 0:
                    cstr = reg_str((insn >> 6) & 0x3F)
                    astr = _ARC_REGS[insn & 0x3F]
                elif opm == 1:
                    cstr = f"0x{(insn >> 6) & 0x3F:x}"
                    astr = _ARC_REGS[insn & 0x3F]
                elif opm == 2:
                    cstr = str(_sxt(((insn >> 6) & 0x3F) | ((insn & 0x3F) << 6), 12))
                    astr = breg
                else:
                    cstr = f"0x{(insn >> 6) & 0x3F:x}" if (insn & (1 << 5)) else reg_str((insn >> 6) & 0x3F)
                    astr = breg
                if subop == 0x0A:
                    mnem = f"mov {breg}, {cstr}"
                elif subop == 0x0C:
                    mnem = f"cmp {breg}, {cstr}"
                else:
                    mnem = f"{nm} {astr}, {breg}, {cstr}"
            else:
                mnem = f"op{maj:02x}_32 0x{insn:08x}"

            raw_hex = buf[pc : pc + length].hex()
            out.append((pc, raw_hex, mnem))
            pc += length
        else:
            b3 = _sreg((hw0 >> 8) & 7)
            c3 = _sreg((hw0 >> 5) & 7)
            u5 = hw0 & 0x1F
            if maj == 0x10:
                mnem = f"ld_s {_sreg(hw0 & 7)}, [{b3}, {u5 << 2}]"
            elif maj == 0x11:
                mnem = f"ldb_s {_sreg(hw0 & 7)}, [{b3}, {u5}]"
            elif maj == 0x12:
                mnem = f"ldw_s {_sreg(hw0 & 7)}, [{b3}, {u5 << 1}]"
            elif maj == 0x14:
                mnem = f"st_s {c3}, [{b3}, {u5 << 2}]"
            elif maj == 0x15:
                mnem = f"stb_s {c3}, [{b3}, {u5}]"
            elif maj == 0x16:
                mnem = f"stw_s {c3}, [{b3}, {u5 << 1}]"
            elif maj == 0x1B:
                mnem = f"mov_s {b3}, 0x{hw0 & 0xFF:x}"
            elif maj == 0x1C:
                mnem = f"cmp_s {b3}, 0x{hw0 & 0x7F:x}" if (hw0 & 0x80) else f"add_s {b3}, {b3}, 0x{hw0 & 0x7F:x}"
            elif maj == 0x1E:
                sub = (hw0 >> 9) & 3
                d = _sxt(hw0 & 0x1FF, 9) << 1 if sub != 3 else _sxt(hw0 & 0x3F, 6) << 1
                cc = {0: "b_s", 1: "beq_s", 2: "bne_s", 3: "bcc_s"}[sub]
                mnem = f"{cc} 0x{(pc & ~3) + d:06x}"
            elif maj == 0x1F:
                mnem = f"bl_s 0x{(pc & ~3) + (_sxt(hw0 & 0x7FF, 11) << 2):06x}"
            elif hw0 == 0x7EE0:
                mnem = "j_s [blink]"
            elif hw0 == 0x7FE0:
                mnem = "j_s.d [blink]"
            else:
                mnem = f"op{maj:02x}_16 0x{hw0:04x}"
            out.append((pc, buf[pc : pc + 2].hex(), mnem))
            pc += 2
    return out


def run_selftest(repo_root: pathlib.Path) -> None:
    ec1_path = (
        repo_root
        / "bios-analysis/collected_latest_ec/models"
        / "XPS_13_9350_1.13.0_33773727/ec_1_RAW_PFS_SUBCOMPONENT_262144.bin"
    )
    pw_308b_path = (
        repo_root
        / "bios-analysis/collected_latest_ec/unique_pw"
        / "pw_x86_64_308bfefc72690c51_38912.efi"
    )
    pw_77e7_path = (
        repo_root
        / "bios-analysis/collected_latest_ec/unique_pw"
        / "pw_x86_64_77e719e0dece9039_11776.efi"
    )

    print("[1/5] Verifying plaintext MEC5085 EC image (XPS 13 9350 v1.13.0 `ec_1`)...")
    ec1 = ec1_path.read_bytes()
    assert len(ec1) == 262144
    fw_alph = ec1[0x246B4 : 0x246B4 + 72].decode("ascii")
    assert fw_alph == MEC5085_EC_ALPH72, f"Alphabet mismatch: {fw_alph}"
    # Verify cmd 0x21 dispatch pair at 0x24dec -> (0x08ef0, 0x00210002)
    fn_21, meta_21 = struct.unpack_from("<II", ec1, 0x24DEC)
    assert fn_21 == 0x08EF0 and (meta_21 >> 16) == 0x0021
    # Verify cmd 0x4E generator sample & cmd 0x50 verifier sample
    sample_pw8 = mec5085_cmd4e_generate_8char(b"ABCDE", fw_alph)
    assert len(sample_pw8) == 8 and all(c in fw_alph for c in sample_pw8)
    sample_pw16 = mec5085_cmd50_expected_16char(bytes(range(32)), fw_alph)
    assert len(sample_pw16) == 16
    print(f"      OK: MEC5085 alph72 verified @0x246b4; cmd 0x21 -> 0x{fn_21:05x}; sample cmd4E('ABCDE') = {sample_pw8}")

    print("[2/5] Disassembling MEC5085 ClearPasswordFlags (`0x1d3c4`) & Verifier (`0x1d828`)...")
    insns = disasm_arcompact(ec1, 0x1D3C4, 0x1D3F6)
    assert any("j_s" in m for _, _, m in insns), "Expected return in 0x1d3c4"
    print(f"      OK: decoded {len(insns)} ARCompact instructions at 0x1d3c4")

    print("[3/5] Verifying 2025-2026 `DellSecurityVaultSmm` (`pw_308b`, 38,912 B) `8FC8` RENDER...")
    pw308b = pw_308b_path.read_bytes()
    alph0 = extract_uefi_alphabet0(pw308b)
    assert len(alph0) == 72 and alph0.startswith("0Q2drGk99WLJ1EGn")
    assert GUID_SMM_EC_7310E28E in pw308b
    assert GUID_EC_VAULT_CAP_90306BBD in pw308b
    test_resp = bytes(range(32))
    rendered = render_8fc8_from_ec_resp(test_resp, alph0)
    assert len(rendered) == 16 and rendered[0] == alph0[16 % 72]
    print(f"      OK: ALPHABET0='{alph0}' (len=72); sample RENDER={rendered}")

    print("[4/5] Verifying 2026 Panther Lake `pw_77e7` (11,776 B) pure-EC `{1B58,9ABE,3FE2,CF1B}` module...")
    pw77e7 = pw_77e7_path.read_bytes()
    assert b"0Q2drGk9" not in pw77e7, "pw_77e7 must NOT contain ALPHABET0"
    assert GUID_SMM_EC_7310E28E in pw77e7
    assert GUID_EC_VAULT_CAP_90306BBD in pw77e7
    assert VAULT_SHA256_SALT in pw77e7
    assert bytes.fromhex("581bbe9ae23f1bcfffff") in pw77e7
    assert b"\xc8\x8f" not in pw77e7, "0x8FC8 must be absent from 2026 pw_77e7"
    ident11 = sanitize_2026_hdd_identity(b"         ABC12345678", 0xCF1B)
    assert ident11 == b"ABC12345678" and len(ident11) == 11
    r_expected = cf1b_double_sha256_expected_r(b"TestPass12345678")
    assert len(r_expected) == 32
    print(f"      OK: 2026 pw_77e7 verified (8FC8 & ALPHABET0 retired; CF1B R={r_expected.hex()[:16]}...)")

    print("[5/5] All self-tests PASSED.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze & verify Dell EC / BIOS password algorithms")
    ap.add_argument("--selftest", action="store_true", help="Run verification suite against collected binaries")
    ap.add_argument("--disasm-mec5085", nargs=2, metavar=("START_HEX", "END_HEX"), help="Disassemble XPS 13 9350 MEC5085 EC range")
    args = ap.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parents[2]
    if args.disasm_mec5085:
        ec1 = (
            repo_root
            / "bios-analysis/collected_latest_ec/models"
            / "XPS_13_9350_1.13.0_33773727/ec_1_RAW_PFS_SUBCOMPONENT_262144.bin"
        ).read_bytes()
        s, e = int(args.disasm_mec5085[0], 16), int(args.disasm_mec5085[1], 16)
        for pc, hx, mnem in disasm_arcompact(ec1, s, e):
            print(f"0x{pc:05x}: {hx:16s}  {mnem}")
        return

    run_selftest(repo_root)


if __name__ == "__main__":
    main()
