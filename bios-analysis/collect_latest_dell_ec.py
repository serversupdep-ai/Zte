#!/usr/bin/env python3
"""
collect_latest_dell_ec.py — Comprehensive 2024–2026 Dell EC & BIOS Password
Algorithm Collector and Deep Unpacker.

Designed to run both locally (`--local-file`) and on GitHub Actions (`--lvfs-sweep`)
with full internet egress to `cdn.fwupd.org` / `fwupd.org` / `dl.dell.com`.

Key improvements over legacy `collect_from_catalog.py`:
1. Sweeps the live LVFS catalog (`firmware.xml.zst` / `firmware.xml.gz`) across ALL
   2024–2026 Dell product lines previously missing from `relay/lvfs_catalog.txt`:
   - Standalone Dell EC / KBC / MCU updates (`DGX_Spark_EC_FW`, etc.)
   - Dell Pro / Pro Plus / Pro Max / Pro Precision / Pro Rugged (AMD & Intel, 2025–2026)
   - Dell Pro Essential & Dell 14/15/16 ODM laptops (`PV14255`, `DC14255`, `PV15260`, `D14265`, etc.)
   - Inspiron & Vostro (Intel & AMD Barcelo/Dali — Compal/Wistron/Quanta ITE/Nuvoton ECs)
   - XPS (`9340`, `9345`, `9350`, `DA14260`), Alienware (`DA15260`, `AC16250`), G15/G16 (`5530`/`7630`)
   - Latest Latitude (`3450`/`3550`, `5450`, `5550`, `7350`, `7455`/`5455` if present)
2. Removes the `< 1 MB` `.cab` file filter that previously discarded dedicated EC capsules.
3. Unpacks ALL Dell container layers:
   - `.cab` (`7z`), UEFI FMP / Capsule headers, Dell `PFS.HDR.` at ANY offset + XML/PMInfo manifest
   - `platomav/BIOSUtilities` (`DellPfsExtract`) when available
   - AMD PSP `0x100`-aligned `zlib` streams + UEFI `EE4E5898` LZMA GUID sections + XZ + Zstd
   - Insyde `$_IFLASH_EC_IMG_` / `$_IFLASH` blocks + AMI `_AMIPFAT` (BiosGuard) header inspection
4. Captures ALL EC architectures (not only `PHCM@0`):
   - Microchip `PHCM` / `MCHP` (MEC15xx / MEC17xx) at ANY offset, flagging `byte@6` plaintext vs sealed
   - ITE (`IT557x` / `IT8987` / `IT85xx` — `A5 A5 A5 A5 A5 A5` signature, 8051 / Andes N8 / RISC-V)
   - Nuvoton (`NPCX` / `NPCE` — `0x8040E000` boot descriptor, `55 AA` header, Cortex-M4)
   - Plaintext Cortex-M / ARM / non-PE firmware sections (`32 KB .. 1.5 MB`) in PFS / FMP capsules
5. Captures & deduplicates ALL UEFI/PEI/SMM/ARM64 password modules (`ALPHABET0`, `8dfc7b25`,
   `C065AEAB`, `7310E28E` SMM EC protocol, `8FC8`/`CF1B` suffix tables, classic `23456789abcdefgh...`),
   scanning whether any module implements a non-EC software `8FC8` generator or novel transport.
"""

import argparse
import concurrent.futures
import gzip
import hashlib
import io
import json
import lzma
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

LZMA_GUID = bytes.fromhex("98584eee143959429d6edc7bd79403cf")
EC_REGION_DESC = bytes.fromhex("00e04080")

# Markers for password modules and EC algorithm engines
MARKERS = {
    "ALPHABET0": b"0Q2drGk99WLJ1EGnqR5y3DGr",
    "ALPH_SHORT": b"0Q2drGk99",
    "SALT_8dfc7b25": bytes.fromhex("257bfc8d"),
    "GUID_C065AEAB": bytes.fromhex("abae65c01cdd494dbd334578e106c700"),
    "GUID_SMM_EC_7310E28E": bytes.fromhex("8ee21073ea966043946e5adc6be8f531"),
    "CLASSIC_ALPH32": b"23456789abcdefghijkmnpqrstuvwxyz",
    "SHA256_K0_BE": bytes.fromhex("428a2f9871374491"),
    "SHA256_K0_LE": bytes.fromhex("982f8a4291443771"),
    "MD5_K0_LE": bytes.fromhex("78a46ad756b7c7e8"),
    "AES_SBOX": bytes.fromhex("637c777bf26b6fc5"),
    "FAM_8FC8": bytes.fromhex("c88f"),
    "FAM_CF1B": bytes.fromhex("1bcf"),
    "FAM_9ABE": bytes.fromhex("be9a"),
}

FAMILIES_U16 = [0x1B58, 0x9ABE, 0x3FE2, 0xCF1B, 0x8FC8]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    # Exclude pure 0xFF / 0x00 padding runs when measuring active entropy if desired,
    # here standard Shannon entropy on sample
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def active_entropy(b: bytes) -> float:
    """Entropy over 4 KB blocks excluding pure 0xFF or 0x00 erased blocks."""
    active = bytearray()
    for off in range(0, len(b), 4096):
        blk = b[off : off + 4096]
        if blk != b"\xff" * len(blk) and blk != b"\x00" * len(blk):
            active.extend(blk)
        if len(active) >= 131072:
            break
    return entropy(bytes(active)) if active else 0.0


def family_table_hits(b: bytes) -> list:
    """Find offsets where >=3 Dell EC suffixes appear within 32 bytes."""
    fbytes = [struct.pack("<H", f) for f in FAMILIES_U16]
    hits = []
    # Quick pre-check: must contain 8FC8 or CF1B
    if b"\xc8\x8f" not in b and b"\x1b\xcf" not in b:
        return hits
    idx = 0
    while True:
        idx = b.find(b"\xc8\x8f", idx)
        if idx < 0:
            break
        win = b[max(0, idx - 32) : idx + 32]
        cnt = sum(1 for fb in fbytes if fb in win)
        if cnt >= 3:
            # Also extract any adjacent 2-byte uppercase-hex-like suffixes or u16s
            hits.append(idx)
            idx += 32
        else:
            idx += 2
    return hits


def scan_ec_algorithm_signals(b: bytes) -> dict:
    """Scan an EC or firmware binary for Dell EC_GENERATE / mailbox / crypto signals."""
    sig = {}
    for k, pat in MARKERS.items():
        if k in ("FAM_8FC8", "FAM_CF1B", "FAM_9ABE"):
            continue
        c = b.count(pat)
        if c:
            sig[k] = c
    ft = family_table_hits(b)
    if ft:
        sig["family_table_offsets"] = [hex(x) for x in ft[:6]]
    # Check Microchip MEC14xx/15xx/17xx mailbox MMIOs
    for mname, mval in [
        ("MEC_MBOX_400F0110", 0x400F0110),
        ("MEC_MBOX_400F0112", 0x400F0112),
        ("MEC_MBOX_400F0000", 0x400F0000),
        ("MEC_ESPI_400F3400", 0x400F3514),
        ("MEC_CRYPTO_4000FC00", 0x4000FC20),
    ]:
        c = b.count(struct.pack("<I", mval))
        if c:
            sig[mname] = c
    # Check x86/EC I/O port 0x910 / 0x911 pairs nearby
    p910 = [m.start() for m in re.finditer(rb"\x10\x09", b)]
    near_911 = 0
    for p in p910[:200]:
        if b"\x11\x09" in b[max(0, p - 32) : p + 32]:
            near_911 += 1
    if near_911:
        sig["io_910_911_pairs"] = near_911
    # Check ITE signature
    ite_m = re.search(rb"\xa5{6,16}[\x85\xa5\xaa\xb5\x94\x75\x65]", b)
    if ite_m:
        sig["ite_sig_offset"] = hex(ite_m.start())
    # Extract notable version/chip ASCII strings
    strs = []
    for m in re.finditer(rb"[ -~]{6,48}", b):
        s = m.group(0).decode("latin1")
        sl = s.lower()
        if any(w in sl for w in ["phcm", "mchp", "mec1", "ite", "it55", "it89", "npcx", "nuvoton",
                                 "ec_ver", "kbc", "compal", "quanta", "wistron", "inventec", "dell",
                                 "birman", "password", "service", "8fc8", "cf1b"]):
            if s not in strs:
                strs.append(s)
        if len(strs) >= 15:
            break
    if strs:
        sig["notable_strings"] = strs
    return sig


def carve_pe_around(buf: bytes, pos: int) -> bytes | None:
    """Carve a clean PE32 / PE32+ image containing offset `pos`."""
    start_lim = max(0, pos - 0x80000)
    cur = pos
    while cur >= start_lim:
        mz = buf.rfind(b"MZ", start_lim, cur + 1)
        if mz < 0:
            break
        if mz + 0x100 <= len(buf):
            pe_off = struct.unpack_from("<I", buf, mz + 0x3C)[0]
            if 0x20 <= pe_off < 0x400 and mz + pe_off + 0x58 <= len(buf):
                if buf[mz + pe_off : mz + pe_off + 4] == b"PE\x00\x00":
                    img_sz = struct.unpack_from("<I", buf, mz + pe_off + 0x50)[0]
                    # Compute raw end from section headers too (more accurate than SizeOfImage on TE/packed)
                    nsec = struct.unpack_from("<H", buf, mz + pe_off + 6)[0]
                    opt_sz = struct.unpack_from("<H", buf, mz + pe_off + 20)[0]
                    sec_base = mz + pe_off + 24 + opt_sz
                    max_raw = img_sz
                    if sec_base + nsec * 40 <= len(buf) and 0 < nsec <= 32:
                        raw_end = 0
                        for i in range(nsec):
                            rsz, rptr = struct.unpack_from("<2I", buf, sec_base + i * 40 + 16)
                            if rptr + rsz > raw_end:
                                raw_end = rptr + rsz
                        if 0x400 <= raw_end <= 0x200000:
                            max_raw = raw_end
                    if 0x400 <= max_raw <= 0x200000 and mz + max_raw <= len(buf) and pos < mz + max(max_raw, img_sz):
                        return buf[mz : mz + max_raw]
        cur = mz - 1
    return None


def analyze_pw_pe(pe: bytes) -> dict:
    """Inspect a UEFI/PEI/ARM64 password PE module for architecture and EC vs software path."""
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    mach = struct.unpack_from("<H", pe, pe_off + 4)[0]
    mach_map = {0x8664: "x86_64", 0x014C: "i386", 0xAA64: "arm64", 0x01C2: "arm_thumb"}
    arch = mach_map.get(mach, hex(mach))
    info = {
        "arch": arch,
        "size": len(pe),
        "has_alphabet0": b"0Q2drGk99" in pe,
        "has_salt_8dfc7b25": bytes.fromhex("257bfc8d") in pe,
        "has_guid_c065aeab": bytes.fromhex("abae65c01cdd494d") in pe,
        "has_smm_ec_7310e28e": bytes.fromhex("8ee21073ea966043") in pe,
        "has_classic_alph32": b"23456789abcdefghijkmnpqrstuvwxyz" in pe,
        "io_910_911": (b"\x10\x09" in pe and b"\x11\x09" in pe),
        "family_tables": len(family_table_hits(pe)),
    }
    # Check for cmd 0x21 session pattern (c6 .. 21 + 03 + 06 nearby)
    info["has_cmd21_sub3"] = bool(re.search(rb"\x21.{0,24}\x03.{0,24}\x06", pe, re.DOTALL))
    return info


def parse_dell_pfs_sections(buf: bytes) -> list:
    """Native Dell PFS.HDR. parser that works on v1/v2 PFS headers (32-bit or 64-bit sizes)
    AND via uefi_firmware.pfs.PFSFile, returning [(sec_idx, guid_hex, ver_str, data_bytes)]."""
    out = []
    # Try uefi_firmware PFSFile first
    try:
        from uefi_firmware.pfs import PFSFile
        pfs = PFSFile(buf)
        pfs.process()
        for idx, s in enumerate(getattr(pfs, "sections", []) or []):
            sd = getattr(s, "section_data", None)
            gh = ""
            for attr in ("guid", "uuid"):
                gv = getattr(s, attr, None)
                if gv:
                    gh = str(gv)
                    break
            if isinstance(sd, (bytes, bytearray)) and len(sd) >= 16:
                out.append((idx, gh, "", bytes(sd)))
        if out:
            return out
    except Exception:
        pass

    # Fallback manual PFS v1/v2 walk (`PFS.HDR.` + u32 hdr_ver + u32 payload_size)
    if buf[:8] != b"PFS.HDR." or len(buf) < 0x60:
        return out
    hdr_ver, pay_sz = struct.unpack_from("<II", buf, 8)
    pos = 0x10
    end = min(len(buf), 0x10 + pay_sz)
    idx = 0
    for hdr_sz in (0x48, 0x58):
        out_try = []
        p = pos
        ok = True
        while p + hdr_sz <= end and idx < 64:
            guid_b = buf[p : p + 16]
            g_str = guid_b.hex()
            if hdr_sz == 0x48:
                dsz, dsig, msz, msig = struct.unpack_from("<4I", buf, p + 0x28)
            else:
                dsz, dsig, msz, msig = struct.unpack_from("<4Q", buf, p + 0x28)
            total = hdr_sz + dsz + dsig + msz + msig
            if dsz == 0 and msz == 0 or total <= hdr_sz or p + total > end + 64:
                ok = False
                break
            sd = buf[p + hdr_sz : p + hdr_sz + dsz]
            out_try.append((idx, g_str, f"v{hdr_ver}", sd))
            p += total
            idx += 1
        if ok and out_try:
            return out_try
    return out


def unpack_deep(raw_blob: bytes, label: str = "pkg") -> tuple[list, list]:
    """Unpack all nested containers/streams from `raw_blob`.
    Returns:
      - streams: list of (stream_label, bytes)
      - pfs_manifest: list of dicts describing direct PFS/iflash sections
    """
    streams = [(label, raw_blob)]
    pfs_manifest = []
    seen_sha = {sha256(raw_blob)}

    def add_stream(slbl: str, data: bytes):
        if not data or len(data) < 64:
            return
        k = sha256(data)
        if k in seen_sha:
            return
        seen_sha.add(k)
        streams.append((slbl, data))

    # 1. Try platomav BIOSUtilities DellPfsExtract if installed
    for bu_path in ("/tmp/BIOSUtilities", os.path.join(HERE, "tools", "BIOSUtilities")):
        if os.path.isdir(bu_path) and bu_path not in sys.path:
            sys.path.insert(0, bu_path)
    try:
        from biosutilities.dell_pfs_extract import DellPfsExtract
        import contextlib
        with tempfile.TemporaryDirectory() as td:
            ext = DellPfsExtract(input_object=bytearray(raw_blob), extract_path=td, padding=8)
            if ext.check_format():
                with contextlib.redirect_stdout(io.StringIO()):
                    ext.parse_format()
                for root, _dirs, files in os.walk(td):
                    for fn in sorted(files):
                        fp = os.path.join(root, fn)
                        data = open(fp, "rb").read()
                        rel = os.path.relpath(fp, td)
                        pfs_manifest.append({
                            "source": "DellPfsExtract",
                            "name": rel,
                            "size": len(data),
                            "entropy": round(active_entropy(data), 3),
                            "head16": data[:16].hex(),
                        })
                        add_stream(f"bu:{rel}", data)
    except Exception:
        pass

    # 2. Dell HDR zlib streams (AA EE AA 76 1B EC BB 20 F1 E6 51 . 78 9C)
    for m in re.finditer(rb"\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51.\x78", raw_blob, re.DOTALL):
        zpos = m.end() - 1
        try:
            dec = zlib.decompressobj().decompress(raw_blob[zpos : zpos + 0x5000000])
            add_stream(f"dell_hdr_zlib@0x{zpos:X}", dec)
        except Exception:
            pass

    # 3. XZ and Zstd streams
    for m in re.finditer(rb"\xfd7zXZ\x00", raw_blob):
        try:
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(raw_blob[m.start() :])
            add_stream(f"xz@0x{m.start():X}", dec)
        except Exception:
            pass
    try:
        import zstandard as zstd
        for m in re.finditer(rb"\x28\xb5\x2f\xfd", raw_blob):
            try:
                dctx = zstd.ZstdDecompressor()
                dec = dctx.decompress(raw_blob[m.start() :], max_output_size=256 * 1024 * 1024)
                add_stream(f"zstd@0x{m.start():X}", dec)
            except Exception:
                pass
    except ImportError:
        pass

    # 4. BFS expansion over discovered streams (PFS.HDR., $_IFLASH, AMD 0x100 zlib, UEFI LZMA)
    qi = 0
    while qi < len(streams) and len(streams) < 400:
        slbl, cur = streams[qi]
        qi += 1

        # 4a. Dell PFS.HDR. at ANY offset in `cur`
        off = 0
        while True:
            off = cur.find(b"PFS.HDR.", off)
            if off < 0:
                break
            secs = parse_dell_pfs_sections(cur[off:])
            for sidx, gstr, ver, sd in secs:
                # Check if XML / text PMInfo manifest
                txt_snip = ""
                if len(sd) < 65536 and (b"<?xml" in sd[:256] or b"<Firmware" in sd[:512] or b"Component" in sd[:512]):
                    txt_snip = sd.decode("utf-8", "ignore")[:2000]
                pfs_manifest.append({
                    "source": f"{slbl}->pfs@0x{off:X}[{sidx}]",
                    "guid": gstr,
                    "size": len(sd),
                    "entropy": round(active_entropy(sd), 3),
                    "head16": sd[:16].hex(),
                    "xml_hint": txt_snip[:400] if txt_snip else "",
                })
                add_stream(f"{slbl}->pfs@0x{off:X}[{sidx}:{gstr[:8]}]", sd)
            off += 8

        # 4b. Insyde $_IFLASH blocks (`$_IFLASH_EC_IMG_`, `$_IFLASH_BIOSIMG`, etc.)
        for im in re.finditer(rb"\$_IFLASH_[A-Z0-9_]{4,8}", cur):
            ipos = im.start()
            itag = cur[ipos : ipos + 16].decode("latin1", "ignore")
            if ipos + 24 <= len(cur):
                tsz, dsz = struct.unpack_from("<II", cur, ipos + 16)
                if 0x1000 <= dsz <= 0x4000000 and ipos + 24 + dsz <= len(cur):
                    ipay = cur[ipos + 24 : ipos + 24 + dsz]
                    pfs_manifest.append({
                        "source": f"{slbl}->iflash@0x{ipos:X}",
                        "name": itag,
                        "size": len(ipay),
                        "entropy": round(active_entropy(ipay), 3),
                        "head16": ipay[:16].hex(),
                    })
                    add_stream(f"{slbl}->{itag}@0x{ipos:X}", ipay)

        # 4c. AMD PSP 0x100-aligned zlib streams (only scan large >1MB containers)
        if len(cur) >= 0x100000 and "zlib@" not in slbl and "lzma@" not in slbl:
            for zm in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", cur):
                zpos = zm.start()
                if (zpos & 0xFF) == 0:
                    try:
                        dec = zlib.decompressobj().decompress(cur[zpos : zpos + 0x1000000])
                        if len(dec) >= 0x2000:
                            add_stream(f"{slbl}->zlib@0x{zpos:X}", dec)
                    except Exception:
                        pass

        # 4d. UEFI LZMA GUID sections (EE4E5898-3914-4259-9D6E-DC7BD79403CF)
        if len(cur) >= 0x4000 and slbl.count("lzma@") < 2:
            for lm in re.finditer(re.escape(LZMA_GUID), cur):
                gpos = lm.start()
                if gpos >= 4 and gpos + 24 <= len(cur):
                    hdr_off = gpos - 4
                    sec_hdr = struct.unpack_from("<I", cur, hdr_off)[0]
                    sec_len = sec_hdr & 0xFFFFFF
                    if (sec_hdr >> 24) == 0x02:
                        doff = struct.unpack_from("<H", cur, hdr_off + (28 if sec_len == 0xFFFFFF else 20))[0]
                        if sec_len == 0xFFFFFF:
                            sec_len = struct.unpack_from("<I", cur, hdr_off + 24)[0]
                        if 0 < doff < sec_len and hdr_off + sec_len <= len(cur):
                            pay = cur[hdr_off + doff : hdr_off + sec_len]
                            for try_off in (0, 4):
                                try:
                                    dec = lzma.decompress(pay[try_off:])
                                    if len(dec) >= 0x1000:
                                        add_stream(f"{slbl}->lzma@0x{hdr_off:X}", dec)
                                    break
                                except Exception:
                                    pass
            # Also scan raw LZMA-alone streams (`5d 00 00 80 00` + valid uncompressed size <= 64MB)
            for lm2 in re.finditer(rb"\x5d\x00\x00\x80\x00", cur):
                lpos = lm2.start()
                if lpos + 13 <= len(cur):
                    usz = struct.unpack_from("<Q", cur, lpos + 5)[0]
                    if 0x4000 <= usz <= 0x4000000:
                        try:
                            dec = lzma.decompress(cur[lpos : lpos + 0x1800000])
                            if len(dec) == usz:
                                add_stream(f"{slbl}->lzma_raw@0x{lpos:X}", dec)
                        except Exception:
                            pass

            # Also unpack UEFI _FVH volumes via uefi_firmware AutoParser (handles Tiano/EFI standard compression)
            if b"_FVH" in cur and slbl.count("ufv") < 1 and len(cur) <= 0x3000000:
                try:
                    from uefi_firmware import AutoParser
                    ap_obj = AutoParser(cur).parse()
                    if ap_obj is not None:
                        def _walk_ufv(o):
                            for ch in getattr(o, "objects", []) or []:
                                for attr in ("_data", "data", "content"):
                                    v = getattr(ch, attr, None)
                                    if isinstance(v, (bytes, bytearray)) and len(v) >= 4096:
                                        add_stream(f"{slbl}->ufv", bytes(v))
                                        break
                                _walk_ufv(ch)
                        _walk_ufv(ap_obj)
                except Exception:
                    pass

    return streams, pfs_manifest


def extract_ec_and_pw_from_streams(streams: list) -> tuple[list, list]:
    """Identify all EC candidates and password PE modules across unpacked streams."""
    ec_candidates = []
    pw_modules = []
    seen_ec = set()
    seen_pw = set()

    for slbl, buf in streams:
        # --- A. Microchip PHCM at ANY offset ---
        off = 0
        while True:
            off = buf.find(b"PHCM", off)
            if off < 0:
                break
            if off + 0x40 <= len(buf):
                ver = buf[off + 4 : off + 8]
                # Validate PHCM header: ver[0] in 0..8, ver[1] in 0..8, ver[3] in (1,2,3,4)
                if ver[0] <= 8 and ver[1] <= 8 and ver[3] in (0, 1, 2, 3, 4):
                    # Determine length: if at 0, whole buf; else up to 320 KB or next FF run
                    max_len = len(buf) - off if off == 0 else min(len(buf) - off, 0x50000)
                    ec_bin = buf[off : off + max_len]
                    h = sha256(ec_bin)
                    if h not in seen_ec:
                        seen_ec.add(h)
                        sealed = bool(ver[2] & 0x80)
                        aent = active_entropy(ec_bin[0x40:])
                        ec_candidates.append({
                            "kind": "PHCM",
                            "stream": f"{slbl}@0x{off:X}",
                            "ver_hex": ver.hex(),
                            "sealed_flag": sealed,
                            "plaintext": (not sealed) and (aent < 7.80),
                            "active_entropy": round(aent, 3),
                            "size": len(ec_bin),
                            "sha256": h,
                            "signals": scan_ec_algorithm_signals(ec_bin),
                            "bytes": ec_bin,
                        })
            off += 4

        # --- B. Insyde $_IFLASH_EC_IMG_ or explicit EC stream ---
        if "_IFLASH_EC" in slbl or ("bu:" in slbl and any(k in slbl.lower() for k in ["ec", "kbc", "mec", "ite", "npcx"])):
            h = sha256(buf)
            if h not in seen_ec and 0x4000 <= len(buf) <= 0x200000:
                seen_ec.add(h)
                aent = active_entropy(buf)
                ec_candidates.append({
                    "kind": "EXPLICIT_EC_SECTION",
                    "stream": slbl,
                    "plaintext": aent < 7.80,
                    "active_entropy": round(aent, 3),
                    "size": len(buf),
                    "sha256": h,
                    "signals": scan_ec_algorithm_signals(buf),
                    "bytes": buf,
                })

        # --- C. ITE EC (`A5`x6+ signature inside 32KB..1MB blob or carved 128KB/256KB window) ---
        if 0x8000 <= len(buf) <= 0x100000:
            ite_m = re.search(rb"\xa5{6,16}[\x85\xa5\xaa\xb5\x94\x75\x65]", buf)
            if ite_m and active_entropy(buf) < 7.75:
                h = sha256(buf)
                if h not in seen_ec:
                    seen_ec.add(h)
                    ec_candidates.append({
                        "kind": "ITE_EC",
                        "stream": f"{slbl}@ite_0x{ite_m.start():X}",
                        "plaintext": True,
                        "active_entropy": round(active_entropy(buf), 3),
                        "size": len(buf),
                        "sha256": h,
                        "signals": scan_ec_algorithm_signals(buf),
                        "bytes": buf,
                    })

        # --- D. Nuvoton EC region descriptor `00 e0 40 80` ---
        idx = 0
        while True:
            idx = buf.find(EC_REGION_DESC, idx)
            if idx < 0:
                break
            if idx + 24 <= len(buf):
                sp, rv = struct.unpack_from("<II", buf, idx + 8)
                if 0x10000000 <= sp <= 0x20100000 and 0x80 <= rv < 0x80000:
                    reg = buf[idx + 0x10 : idx + 0x10 + 0x40000]
                    h = sha256(reg)
                    if h not in seen_ec and len(reg) >= 0x4000:
                        seen_ec.add(h)
                        aent = active_entropy(reg)
                        ec_candidates.append({
                            "kind": "NUVOTON_EC_REGION",
                            "stream": f"{slbl}@0x{idx:X}",
                            "plaintext": aent < 7.75,
                            "active_entropy": round(aent, 3),
                            "size": len(reg),
                            "sha256": h,
                            "signals": scan_ec_algorithm_signals(reg),
                            "bytes": reg,
                        })
            idx += 4

        # --- E. Direct PFS / CAB / BIOSUtilities EC subcomponents or SMM EC-Vault drivers ---
        if ("->pfs@" in slbl or slbl.startswith("cab:") or slbl.startswith("bu:")) and 0x8000 <= len(buf) <= 0x120000:
            if buf[:2] != b"MZ" and buf[:4] != b"PHCM" and b"_FVH" not in buf[:128] and b"PFS.HDR." not in buf[:64]:
                is_npcx_ifuse = buf[:4] == bytes.fromhex("5e4d3b2a")
                is_ec_named = any(k in slbl.lower() for k in ("embedded controller", "ec ", "_ec", "kbc", "mec", "npcx"))
                is_compal_zephyr = b"CompalA31" in buf[:0x1000]
                has_ec_vault_guid = (
                    bytes.fromhex("8ee21073ea966043946e5adc6be8f531") in buf
                    or bytes.fromhex("90306bbd3669f04dbc7368b06fb4e791") in buf
                )
                if is_npcx_ifuse or is_ec_named or is_compal_zephyr or has_ec_vault_guid:
                    aent = active_entropy(buf)
                    is_pfat = b"_AMIPFAT" in buf[:64]
                    if not is_pfat or aent < 7.75:
                        h = sha256(buf)
                        if h not in seen_ec:
                            seen_ec.add(h)
                            ec_candidates.append({
                                "kind": "NPCX993D_IFUSE" if is_npcx_ifuse else "RAW_PFS_SUBCOMPONENT",
                                "stream": slbl,
                                "plaintext": (not is_npcx_ifuse) and (aent < 7.80),
                                "active_entropy": round(aent, 3),
                                "size": len(buf),
                                "sha256": h,
                                "head32": buf[:32].hex(),
                                "signals": scan_ec_algorithm_signals(buf),
                                "bytes": buf,
                            })

        # --- F. UEFI / PEI / SMM / ARM64 Password Modules ---
        for mname in ("ALPH_SHORT", "SALT_8dfc7b25", "GUID_C065AEAB", "CLASSIC_ALPH32"):
            pat = MARKERS[mname]
            poff = 0
            while True:
                poff = buf.find(pat, poff)
                if poff < 0:
                    break
                pe = carve_pe_around(buf, poff)
                if pe is not None:
                    ph = sha256(pe)
                    if ph not in seen_pw:
                        seen_pw.add(ph)
                        pinfo = analyze_pw_pe(pe)
                        pinfo["sha256"] = ph
                        pinfo["stream"] = f"{slbl}@0x{poff:X}"
                        pinfo["trigger_marker"] = mname
                        pinfo["bytes"] = pe
                        pw_modules.append(pinfo)
                poff += len(pat)

    return ec_candidates, pw_modules


# ---------------------------------------------------------------------------
# LVFS Catalog Discovery & Selection
# ---------------------------------------------------------------------------

HEADERS_LIST = [
    {"User-Agent": "fwupd/1.9.27", "Accept": "*/*"},
    {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Referer": "https://fwupd.org/",
    },
]


def http_get(url: str, max_bytes: int = 120 * 1024 * 1024, timeout: int = 180) -> bytes:
    urls = [url]
    if "fwupd.org/downloads/" in url and "cdn.fwupd.org" not in url:
        urls.insert(0, url.replace("https://fwupd.org/downloads/", "https://cdn.fwupd.org/downloads/"))
    last_err = None
    for u in urls:
        for hdr in HEADERS_LIST:
            try:
                req = urllib.request.Request(u, headers=hdr)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.read(max_bytes)
            except Exception as e:
                last_err = e
    raise RuntimeError(f"GET failed for {url}: {last_err}")


def load_lvfs_dell_catalog(allow_net: bool = True) -> list[dict]:
    """Load all Dell components from live cdn.fwupd.org metadata (falling back to local firmware.xml.gz)."""
    xml_bytes = None
    if allow_net:
        for mu in (
            "https://cdn.fwupd.org/downloads/firmware.xml.zst",
            "https://cdn.fwupd.org/downloads/firmware.xml.gz",
        ):
            try:
                print(f"[lvfs] downloading live metadata: {mu}", flush=True)
                raw = http_get(mu, max_bytes=250 * 1024 * 1024, timeout=180)
                if mu.endswith(".zst"):
                    try:
                        import zstandard as zstd
                        xml_bytes = zstd.ZstdDecompressor().decompress(raw, max_output_size=600 * 1024 * 1024)
                    except Exception:
                        p = subprocess.run(["zstd", "-dc"], input=raw, capture_output=True, timeout=120)
                        if p.returncode == 0:
                            xml_bytes = p.stdout
                else:
                    xml_bytes = gzip.decompress(raw)
                if xml_bytes:
                    print(f"[lvfs] parsed live metadata: {len(xml_bytes) // (1024*1024)} MB XML", flush=True)
                    break
            except Exception as e:
                print(f"[lvfs] live metadata {mu} error: {e}", flush=True)

    if not xml_bytes:
        local_gz = os.path.join(HERE, "collected", "raw", "fwupd_meta", "firmware.xml.gz")
        if os.path.exists(local_gz):
            print(f"[lvfs] using local cached metadata: {local_gz}", flush=True)
            xml_bytes = gzip.open(local_gz).read()
        else:
            return []

    dell_comps = []
    for _, el in ET.iterparse(io.BytesIO(xml_bytes), events=("end",)):
        if not el.tag.endswith("component"):
            continue
        cid = (el.findtext("{*}id") or el.findtext("id") or "").strip()
        name = (el.findtext("{*}name") or el.findtext("name") or "").strip()
        summary = (el.findtext("{*}summary") or el.findtext("summary") or "").strip()
        dev = (el.findtext("{*}developer_name") or el.findtext("developer_name") or "").strip()
        hay = f"{cid} {name} {summary} {dev}".lower()
        if "dell" in hay:
            rels = []
            for r in el.iter():
                if r.tag.endswith("release"):
                    ver = r.get("version", "")
                    ts = int(r.get("timestamp") or "0")
                    loc_el = r.find("{*}location")
                    if loc_el is None:
                        loc_el = r.find("location")
                    loc = loc_el.text.strip() if loc_el is not None and loc_el.text else ""
                    if loc.endswith(".cab"):
                        if "://" not in loc:
                            loc = "https://cdn.fwupd.org/downloads/" + loc
                        rels.append({"version": ver, "timestamp": ts, "url": loc})
            if rels:
                rels.sort(key=lambda x: x["timestamp"], reverse=True)
                dell_comps.append({
                    "id": cid,
                    "name": name,
                    "summary": summary,
                    "latest": rels[0],
                    "oldest": rels[-1],
                    "release_count": len(rels),
                })
        el.clear()
    return dell_comps


def score_dell_component(c: dict) -> tuple[int, str]:
    """Assign priority score and category to a Dell LVFS component so we sweep
    every distinct latest 2024–2026 Dell EC architecture & ODM family."""
    txt = f"{c['id']} {c['name']} {c['summary']}".lower()
    # Skip non-system peripherals (NVMe SSDs, docks, monitors, cameras, mice, NICs)
    if any(w in txt for w in ["nvme", "ssd", "pm9", "bm9", "sn5", "sn7", "sn8", "dock", "wd19", "wd22",
                              "sd25", "hd22", "camera", "webcam", "monitor", "display", "keyboard",
                              "mouse", "headset", "retimer", "thunderbolt", "tpm "]):
        return (-1, "skip_peripheral")
    # Skip desktop towers / OptiPlex already heavily covered unless explicit EC
    if any(w in txt for w in [" ec ", "ec firmware", "embedded controller", "kbc", "mcu", "ish "]):
        return (100, "explicit_ec")
    if any(w in txt for w in ["7455", "5455", "9345", "7441", "5441", "snapdragon", "qualcomm", "tributo"]):
        return (98, "snapdragon_arm64")
    if any(w in txt for w in ["pb13255", "pb14255", "pb16255"]):
        return (96, "dell_pro_plus_amd_pb14255")
    if any(w in txt for w in ["pv14255", "dc14255", "pv14265", "d14265", "pv15265"]):
        return (95, "dell_essential_amd_odm")
    if any(w in txt for w in ["pv15260", "pv15250", "dc15250", "dc16250", "d14261", "d15260"]):
        return (93, "dell_essential_intel_odm")
    if any(w in txt for w in ["pc14255", "pc16255", "mc14255", "mc16255"]):
        return (92, "dell_pro_amd_2025")
    if any(w in txt for w in ["3525", "5425", "5625", "7425", "5435", "5635"]):
        return (91, "inspiron_vostro_amd")
    if any(w in txt for w in ["inspiron", "vostro"]) and not any(w in txt for w in ["3020", "3030", "3910", "3710"]):
        return (90, "inspiron_vostro_laptop")
    if any(w in txt for w in ["pb14250", "pa14250", "pc14250", "ma14250", "mb16250", "p314260", "pw514261", "pw714260"]):
        return (89, "dell_pro_intel_2025_2026")
    if any(w in txt for w in ["da14260", "9350", "9340", "da15260", "ac16250", "g15 5530", "g16 7630", "g15 5520"]):
        return (88, "xps_alienware_gaming_latest")
    if any(w in txt for w in ["pr713260", "pr514260", "ra13250", "rb14250", "ra00260"]):
        return (86, "dell_pro_rugged_2025_2026")
    if any(w in txt for w in ["3450", "3550", "3440", "3540", "3340"]):
        return (91, "latitude_3000_odm")
    if any(w in txt for w in ["5450", "5550", "7350", "7450", "9450", "5490", "5690", "3590", "3591"]):
        return (85, "latitude_precision_2024_2025")
    if any(w in txt for w in ["pro max 14", "pro max 16"]):
        return (84, "dell_pro_max")
    if any(w in txt for w in ["optiplex", "tower", "micro", "slim", "all-in-one", "aio", "3020", "3030"]):
        return (10, "desktop_low_prio")
    return (50, "other_dell_laptop")


def select_diverse_targets(comps: list[dict], max_targets: int = 38) -> list[dict]:
    """Select up to `max_targets` distinct, high-priority Dell packages (deduped by cab URL & model family)."""
    scored = []
    for c in comps:
        sc, cat = score_dell_component(c)
        if sc >= 50:
            scored.append((sc, c["latest"]["timestamp"], cat, c))
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)

    chosen = []
    seen_urls = set()
    seen_names = set()
    cat_counts = Counter()
    # Cap per category so every single ODM / SoC / product line gets sampled
    cat_caps = {
        "explicit_ec": 10,
        "snapdragon_arm64": 8,
        "dell_pro_plus_amd_pb14255": 2,
        "dell_essential_amd_odm": 5,
        "dell_essential_intel_odm": 5,
        "dell_pro_amd_2025": 4,
        "inspiron_vostro_amd": 4,
        "inspiron_vostro_laptop": 5,
        "latitude_3000_odm": 4,
        "dell_pro_intel_2025_2026": 6,
        "xps_alienware_gaming_latest": 6,
        "dell_pro_rugged_2025_2026": 2,
        "latitude_precision_2024_2025": 5,
        "dell_pro_max": 2,
        "other_dell_laptop": 3,
    }
    for sc, _ts, cat, c in scored:
        u = c["latest"]["url"]
        norm_name = re.sub(r"[^a-z0-9]", "", c["name"].lower())[:16]
        if u in seen_urls or (norm_name in seen_names and cat not in ("explicit_ec", "snapdragon_arm64")):
            continue
        if cat_counts[cat] >= cat_caps.get(cat, 4):
            continue
        seen_urls.add(u)
        seen_names.add(norm_name)
        cat_counts[cat] += 1
        item = dict(c)
        item["category"] = cat
        item["priority"] = sc
        chosen.append(item)
        if len(chosen) >= max_targets:
            break
    return chosen


def process_one_package(pkg_bytes: bytes, tag: str, meta: dict, out_root: str,
                        pw_dedup_dir: str, sealed_ec_budget: list) -> dict:
    """Unpack one `.cab` or raw firmware file, extract ECs & PW modules, write compact outputs."""
    t0 = time.time()
    inner_blobs = []
    if pkg_bytes[:4] == b"MSCF" or (pkg_bytes[:2] == b"MZ" and len(pkg_bytes) >= 512 * 1024):
        with tempfile.TemporaryDirectory() as td:
            cab_p = os.path.join(td, "pkg.bin")
            open(cab_p, "wb").write(pkg_bytes)
            ext_d = os.path.join(td, "ext")
            subprocess.run(["7z", "x", "-y", f"-o{ext_d}", cab_p], capture_output=True, timeout=300)
            for root, _dirs, files in os.walk(ext_d):
                for fn in sorted(files):
                    # Skip PE resource stub sections (.text/.rdata/.rsrc) when 7z splits a non-SFX PE
                    if fn in (".text", ".rdata", ".data", ".pdata", ".reloc", ".rsrc", "CERTIFICATE"):
                        continue
                    fp = os.path.join(root, fn)
                    if not os.path.isfile(fp):
                        continue
                    sz = os.path.getsize(fp)
                    # Keep EVERY binary >= 4 KB (fixes the old <1MB bug!)
                    if sz >= 4096 and not fn.lower().endswith((".xml", ".metainfo.xml", ".asc", ".p7b", ".p7c", ".cat", ".inf", ".txt", ".dll", ".mui")):
                        inner_blobs.append((f"cab:{fn}", open(fp, "rb").read()))
        if pkg_bytes[:2] == b"MZ":
            inner_blobs.append(("raw", pkg_bytes))
    else:
        inner_blobs.append(("raw", pkg_bytes))

    all_streams = []
    all_pfs_manifest = []
    for ilbl, ibytes in inner_blobs:
        st, pm = unpack_deep(ibytes, ilbl)
        all_streams.extend(st)
        all_pfs_manifest.extend(pm)

    ecs, pws = extract_ec_and_pw_from_streams(all_streams)

    model_dir = os.path.join(out_root, "models", tag)
    os.makedirs(model_dir, exist_ok=True)
    os.makedirs(pw_dedup_dir, exist_ok=True)

    saved_ecs = []
    for idx, ec in enumerate(ecs, 1):
        ebytes = ec.pop("bytes")
        is_plain = ec.get("plaintext", False)
        sig = ec.get("signals", {})
        interesting_sealed = len(sealed_ec_budget) < 6 and ec["size"] <= 0x60000
        save_full = (
            is_plain
            or bool(sig.get("ite_sig_offset"))
            or bool(sig.get("family_table_offsets"))
            or ec["kind"] in ("EXPLICIT_EC_SECTION", "ITE_EC", "NUVOTON_EC_REGION")
            or (ec["kind"] == "RAW_PFS_SUBCOMPONENT" and ec["size"] <= 0x88000 and len(sealed_ec_budget) < 25)
        )
        if save_full and ec["size"] <= 1536 * 1024:
            if not is_plain and ec["kind"] == "RAW_PFS_SUBCOMPONENT":
                sealed_ec_budget.append(tag)
            fn = f"ec_{idx}_{ec['kind']}_{ec['size']}.bin"
            open(os.path.join(model_dir, fn), "wb").write(ebytes)
            ec["saved_file"] = f"models/{tag}/{fn}"
        elif interesting_sealed:
            sealed_ec_budget.append(tag)
            fn = f"ec_{idx}_sealed_{ec['size']}.bin"
            open(os.path.join(model_dir, fn), "wb").write(ebytes)
            ec["saved_file"] = f"models/{tag}/{fn}"
        else:
            # Save 4 KB header stub so header/version/magic can still be inspected locally
            fn = f"ec_{idx}_hdrstub_{ec['size']}.bin"
            open(os.path.join(model_dir, fn), "wb").write(ebytes[:4096])
            ec["saved_file"] = f"models/{tag}/{fn}"
            ec["stub_only"] = True
        saved_ecs.append(ec)

    saved_pws = []
    for pinfo in pws:
        pbytes = pinfo.pop("bytes")
        ph = pinfo["sha256"][:16]
        ufn = f"pw_{pinfo['arch']}_{ph}_{pinfo['size']}.efi"
        upath = os.path.join(pw_dedup_dir, ufn)
        if not os.path.exists(upath):
            open(upath, "wb").write(pbytes)
        pinfo["dedup_file"] = f"unique_pw/{ufn}"
        saved_pws.append(pinfo)

    summary = {
        "tag": tag,
        "meta": meta,
        "elapsed_sec": round(time.time() - t0, 2),
        "inner_files": [(lbl, len(b)) for lbl, b in inner_blobs],
        "unpacked_stream_count": len(all_streams),
        "pfs_sections": all_pfs_manifest[:40],
        "ec_count": len(saved_ecs),
        "plaintext_ec_count": sum(1 for e in saved_ecs if e.get("plaintext")),
        "pw_module_count": len(saved_pws),
        "ecs": saved_ecs,
        "pw_modules": saved_pws,
    }
    json.dump(summary, open(os.path.join(model_dir, "manifest.json"), "w"), indent=2)
    return summary


def write_master_report(summaries: list[dict], all_dell_comps: list[dict], out_root: str):
    """Write `COLLECTION_REPORT.md` and `lvfs_dell_2026_index.json`."""
    json.dump(all_dell_comps, open(os.path.join(out_root, "lvfs_dell_2026_index.json"), "w"), indent=1)
    lines = [
        "# Latest Dell EC & BIOS Password Module Collection Report (2024–2026)",
        "",
        f"- **LVFS Dell components indexed**: {len(all_dell_comps)}",
        f"- **Packages downloaded & deep-unpacked**: {len(summaries)}",
        f"- **Total EC payloads extracted**: {sum(s['ec_count'] for s in summaries)}",
        f"- **Plaintext / low-entropy EC payloads**: {sum(s['plaintext_ec_count'] for s in summaries)}",
        f"- **Total password module instances**: {sum(s['pw_module_count'] for s in summaries)}",
        "",
        "## Per-Model Summary",
        "",
        "| Category | Model / Tag | Version | Streams | ECs | Plaintext ECs | PW Modules | Key EC / PW Signals |",
        "|---|---|---|---:|---:|---:|---:|---|",
    ]
    plaintext_hits = []
    non_smm_ec_pws = []
    for s in summaries:
        cat = s["meta"].get("category", "local")
        ver = s["meta"].get("latest", {}).get("version", "-")
        notes = []
        for e in s["ecs"]:
            k = e["kind"]
            if e.get("plaintext"):
                notes.append(f"**PLAINTEXT {k}** ({e['size']//1024}KB, H={e['active_entropy']})")
                plaintext_hits.append((s["tag"], e))
            else:
                notes.append(f"{k}-sealed({e.get('ver_hex','')}, {e['size']//1024}KB)")
            if e.get("signals", {}).get("notable_strings"):
                notes.append("strs=" + ",".join(e["signals"]["notable_strings"][:2]))
        for p in s["pw_modules"]:
            if p.get("has_alphabet0") and not p.get("has_smm_ec_7310e28e") and not p.get("io_910_911") and p["size"] > 20000:
                non_smm_ec_pws.append((s["tag"], p))
            if p.get("has_classic_alph32"):
                notes.append(f"CLASSIC32({p['arch']},{p['size']}B)")
        lines.append(
            f"| `{cat}` | `{s['tag'][:42]}` | `{ver}` | {s['unpacked_stream_count']} | "
            f"{s['ec_count']} | **{s['plaintext_ec_count']}** | {s['pw_module_count']} | "
            f"{'; '.join(notes[:4]) or '-'} |"
        )

    lines.append("")
    lines.append("## Plaintext / Unsealed EC Candidates")
    if not plaintext_hits:
        lines.append("- None in this batch.")
    else:
        for tag, e in plaintext_hits:
            lines.append(
                f"- **`{tag}`** -> `{e.get('saved_file')}` (`{e['kind']}`, {e['size']} B, "
                f"active_entropy={e['active_entropy']}, signals=`{json.dumps(e.get('signals', {}))}`)"
            )

    lines.append("")
    lines.append("## Password Modules With `ALPHABET0` And Unusual Transport (No `0x910` / No `7310E28E`)")
    for tag, p in non_smm_ec_pws[:30]:
        lines.append(f"- **`{tag}`** -> `{p['dedup_file']}` (`{p['arch']}`, {p['size']} B, `{p['stream']}`)")

    rep_path = os.path.join(out_root, "COLLECTION_REPORT.md")
    open(rep_path, "w").write("\n".join(lines) + "\n")
    print(f"[report] wrote {rep_path}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "collected_latest_ec"))
    ap.add_argument("--local-file", action="append", default=[], help="Test/unpack a local file (.bin/.zip/.cab/.exe)")
    ap.add_argument("--lvfs-sweep", action="store_true", help="Download & unpack latest Dell packages from LVFS")
    ap.add_argument("--wayback-dell-ec", action="store_true", help="Also query Wayback CDX for standalone dl.dell.com EC & Snapdragon/ODM .exe installers")
    ap.add_argument("--max-targets", type=int, default=48)
    ap.add_argument("--workers", type=int, default=5)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    pw_dedup_dir = os.path.join(args.out, "unique_pw")
    sealed_budget = []
    summaries = []

    for lf in args.local_file:
        tag = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(os.path.basename(lf))[0])[:60]
        raw = open(lf, "rb").read()
        if lf.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                for zi in zf.infolist():
                    if zi.file_size >= 4096:
                        ztag = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(os.path.basename(zi.filename))[0])[:60]
                        print(f"[local-zip] unpacking {zi.filename} ({zi.file_size} B)...", flush=True)
                        s = process_one_package(zf.read(zi.filename), ztag, {"category": "local_zip"}, args.out, pw_dedup_dir, sealed_budget)
                        summaries.append(s)
        else:
            print(f"[local] unpacking {lf} ({len(raw)} B)...", flush=True)
            s = process_one_package(raw, tag, {"category": "local_file"}, args.out, pw_dedup_dir, sealed_budget)
            summaries.append(s)

    all_dell_comps = []
    if args.lvfs_sweep:
        all_dell_comps = load_lvfs_dell_catalog(allow_net=True)
        targets = select_diverse_targets(all_dell_comps, max_targets=args.max_targets)
        print(f"[lvfs] selected {len(targets)} high-value Dell targets out of {len(all_dell_comps)} Dell LVFS components", flush=True)

        # Download in parallel, then unpack sequentially (keeps RAM low & deterministic)
        def _dl(t):
            u = t["latest"]["url"]
            b = http_get(u, max_bytes=120 * 1024 * 1024, timeout=240)
            return t, b

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = [pool.submit(_dl, t) for t in targets]
            for idx, fut in enumerate(concurrent.futures.as_completed(futs), 1):
                try:
                    t, cab_bytes = fut.result()
                    cid_short = re.sub(r"[^a-z0-9]", "", t["id"].lower().replace("com.dell.", "").replace("firmware", ""))[-8:]
                    raw_name = f"{t['name'][:40]}_{t['latest']['version']}_{cid_short}"
                    tag = re.sub(r"[^A-Za-z0-9._-]+", "_", raw_name).strip("_")[:68]
                    print(f"[{idx}/{len(targets)}] ({t['category']}) {tag}: downloaded {len(cab_bytes)//1024} KB", flush=True)
                    s = process_one_package(cab_bytes, tag, t, args.out, pw_dedup_dir, sealed_budget)
                    print(f"    -> streams={s['unpacked_stream_count']} ECs={s['ec_count']} (plain={s['plaintext_ec_count']}) PWs={s['pw_module_count']} ({s['elapsed_sec']}s)", flush=True)
                    summaries.append(s)
                except Exception as e:
                    print(f"[{idx}/{len(targets)}] ERROR: {e}", flush=True)

    if args.wayback_dell_ec:
        wb_urls = [
            ("dl_dell_odm_lat3450", "https://dl.dell.com/FOLDER11559391M/1/Latitude_3450_3550_1.3.1.exe"),
            ("dl_dell_ec_tool", "https://dl.dell.com/FOLDER03495025M/5/Firmware_WNXXT_WN32_2.2_A02.EXE"),
        ]
        cdx_queries = [
            "https://web.archive.org/cdx/search/cdx?url=dl.dell.com/FOLDER*&filter=original:.*(9345|7455|5455|7441|EC_FW|Embedded_Controller|_EC_|KBC|Inspiron_14_544|Inspiron_16_564|PV14255|DC14255).*\\.(exe|bin|rcv)&output=json&fl=original&collapse=urlkey&limit=60",
            "https://web.archive.org/cdx/search/cdx?url=downloads.dell.com/FOLDER*&filter=original:.*(9345|7455|5455|7441|EC_FW|Embedded_Controller|_EC_|KBC|Inspiron_14_544|Inspiron_16_564|PV14255|DC14255).*\\.(exe|bin|rcv)&output=json&fl=original&collapse=urlkey&limit=60",
        ]
        seen_wb = {u for _, u in wb_urls}
        for cq in cdx_queries:
            try:
                rows = json.loads(http_get(cq, max_bytes=4 * 1024 * 1024, timeout=45).decode("utf-8", errors="ignore"))
                for row in rows[1:]:
                    if row and row[0] not in seen_wb:
                        u = row[0].replace("http://", "https://")
                        if u not in seen_wb and len(wb_urls) < 16:
                            seen_wb.add(u)
                            wb_urls.append(("wayback_dl_dell", u))
            except Exception as e:
                print(f"[wayback-cdx] {e}", flush=True)

        print(f"[dl.dell.com] fetching {len(wb_urls)} direct Dell .exe/.rcv packages...", flush=True)
        for cat, u in wb_urls:
            try:
                fn_base = os.path.splitext(os.path.basename(u.split("?")[0].split("#")[0]))[0]
                tag = re.sub(r"[^A-Za-z0-9._-]+", "_", f"dell_{fn_base}")[:68]
                b = http_get(u, max_bytes=120 * 1024 * 1024, timeout=180)
                print(f"[dl.dell.com] {tag}: downloaded {len(b)//1024} KB", flush=True)
                s = process_one_package(b, tag, {"category": cat, "priority": 94, "latest": {"version": "exe", "url": u}}, args.out, pw_dedup_dir, sealed_budget)
                print(f"    -> streams={s['unpacked_stream_count']} ECs={s['ec_count']} (plain={s['plaintext_ec_count']}) PWs={s['pw_module_count']} ({s['elapsed_sec']}s)", flush=True)
                summaries.append(s)
            except Exception as e:
                print(f"[dl.dell.com] {u} ERROR: {e}", flush=True)

    if summaries or all_dell_comps:
        summaries.sort(key=lambda x: (x["meta"].get("priority", 0), x["tag"]), reverse=True)
        write_master_report(summaries, all_dell_comps, args.out)


if __name__ == "__main__":
    main()
