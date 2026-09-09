#!/usr/bin/env python3
"""
analyze_dell_bios.py — Dell BIOS package analyzer / unpacker.

Decrypts (i.e. *unpacks*) Dell BIOS update packages such as:
    OptiPlex_3090_2.0.7.exe        (full DUP installer)
    BIOS_IMG.rcv                   (BIOS recovery image, same container family)

These files are NOT user-encrypted. They are PE executables that wrap a
compressed (zlib / xz) "HDR"/"PKG" container, which in turn holds a Dell PFS
package with the real firmware images (BIOS region, Intel ME, descriptors...).

Pipeline implemented here:
  1. Identify input (PE / Dell HDR / Dell PKG / Dell PFS / raw UEFI FV)
  2. Carve + decompress embedded streams (Dell HDR zlib, Dell PKG 7zXZ,
     generic zlib, LZMA-alone)
  3. Extract Dell PFS via biosutilities (platomav/BIOSUtilities)
  4. Parse UEFI firmware volumes via uefi_firmware (uefi-firmware-parser)
  5. Collect version/platform strings and emit a markdown report

Usage:
  python3 analyze_dell_bios.py <input-file> [output-dir]

Dependencies:
  pip install pefile uefi_firmware
  biosutilities staged at tools/BIOSUtilities (optional, for PFS extraction)
"""

import io
import json
import contextlib
import os
import re
import struct
import subprocess
import sys
import zlib

try:
    import pefile
except ImportError:
    pefile = None

# --------------------------------------------------------------------------
# Signatures (aligned with platomav/BIOSUtilities common/patterns.py and
# T-vK/DellBiosUnpackerPOC hdr-unpack.py)
# --------------------------------------------------------------------------

# Dell "HDR" zlib container: <u32 le size> <AA EE AA 76 1B EC BB 20 F1 E6 51>
#                                  <u8 zlib hdr 78 9C> <zlib stream>
PAT_DELL_HDR_FULL = re.compile(
    rb'(.{4})\xAA\xEE\xAA\x76\x1B\xEC\xBB\x20\xF1\xE6\x51(.)\x78\x9C',
    flags=re.DOTALL)

# Dell "PKG" xz container
PAT_DELL_PKG = re.compile(rb'\x13\x55\x00.{45}7zXZ', flags=re.DOTALL)

# UEFI firmware volume signature, at FV header offset 0x28
FVH_SIG = b'_FVH'

# Interesting strings to hunt for in outputs
INTERESTING = [
    rb'\$BVDT', rb'Dell Inc', rb'OptiPlex', rb'Precision', rb'Latitude',
    rb'Inspiron', rb'XPS', rb'_AMIPFAT', rb'\$_IFLASH', rb'Insyde',
    rb'Aptio', rb'AMI ', rb'SMM', rb'Capsule', rb'SetupUtility',
]


def log(msg='', end='\n'):
    print(msg, end=end, flush=True)


def find_all(pattern: bytes, data: bytes):
    offs = []
    start = 0
    while True:
        i = data.find(pattern, start)
        if i < 0:
            return offs
        offs.append(i)
        start = i + 1


# --------------------------------------------------------------------------
# Stage 1 — identification
# --------------------------------------------------------------------------

def identify(data: bytes) -> list:
    kinds = []
    if data[:2] == b'MZ':
        kinds.append('PE-executable')
    if FVH_SIG in data:
        kinds.append('UEFI-FV-present')
    if PAT_DELL_HDR_FULL.search(data):
        kinds.append('Dell-HDR(zlib)-present')
    if PAT_DELL_PKG.search(data):
        kinds.append('Dell-PKG(xz)-present')
    # Dell PFS footer magic
    if b'\xEE\xAA\xEE\x8F\x49\x1B\xE8\xAE\x14\x37\x90' in data:
        kinds.append('Dell-PFS-present')
    return kinds


def pe_report(data: bytes, outdir: str):
    """Dump PE metadata; extract large RCDATA resources (some DUPs embed the
    payload there)."""
    if pefile is None or data[:2] != b'MZ':
        return []
    info = {}
    carved = []
    try:
        pe = pefile.PE(data=data)
    except Exception as e:  # noqa: BLE001
        log(f'  [!] PE parse failed: {e}')
        return carved
    info['machine'] = hex(pe.FILE_HEADER.Machine)
    info['timestamp'] = pe.FILE_HEADER.TimeDateStamp
    info['sections'] = [(s.Name.decode(errors='replace').rstrip('\x00'),
                         hex(s.VirtualAddress), hex(s.SizeOfRawData))
                        for s in pe.sections]
    overlay_off = pe.get_overlay_data_start_offset()
    info['overlay_offset'] = hex(overlay_off) if overlay_off is not None else None
    info['overlay_size'] = len(data) - overlay_off if overlay_off is not None else 0
    # Resources
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            rsrc = []
            for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                rtype = rt.id if rt.id is not None else str(rt.name)
                for rid in rt.directory.entries:
                    for lang in rid.directory.entries:
                        d = lang.data.struct
                        rsrc.append((str(rtype), str(rid.id or rid.name),
                                     d.OffsetToData, d.Size))
            info['resources'] = rsrc
            # dump any resource > 256 KB (candidate payload)
            for (rtype, rid, off, size) in rsrc:
                if size > 256 * 1024:
                    rva = pe.get_rva_from_offset(off) if isinstance(off, int) else None
                    try:
                        rdata = pe.get_data(off, size) if rva is None else pe.get_memory_mapped_image()[off:off + size]
                    except Exception:  # noqa: BLE001
                        rdata = b''
                    if rdata:
                        p = os.path.join(outdir, f'resource_{rtype}_{rid}_{size}.bin')
                        with open(p, 'wb') as f:
                            f.write(rdata)
                        carved.append((p, rdata))
    except Exception as e:  # noqa: BLE001
        info['resources'] = f'error: {e}'
    with open(os.path.join(outdir, 'pe_metadata.json'), 'w') as f:
        json.dump(info, f, indent=2, default=str)
    log(f'  [PE] machine={info["machine"]} sections={len(info["sections"])} '
        f'overlay={info["overlay_size"]} bytes')
    return carved


# --------------------------------------------------------------------------
# Stage 2 — carving / decompression
# --------------------------------------------------------------------------

def carve_streams(data: bytes, outdir: str):
    """Find and decompress every embedded compressed stream we understand."""
    carved = []

    # -- Dell HDR (zlib) ----------------------------------------------------
    for m in PAT_DELL_HDR_FULL.finditer(data):
        start = m.start()
        size = struct.unpack('<I', m.group(1))[0]
        zstart = m.end() - 2  # position of 78 9C
        blob = None
        # The 78 9C magic is part of the zlib stream; size field counts from it.
        for delta in (0, 2, 4):
            if size and zstart + size - delta <= len(data) and size - delta > 2:
                try:
                    blob = zlib.decompress(data[zstart:zstart + size - delta])
                    break
                except zlib.error:
                    continue
        if blob is None:
            # robust fallback: streaming decompressobj until EOF
            d = zlib.decompressobj()
            try:
                blob = d.decompress(data[zstart:])
            except zlib.error:
                blob = None
        if blob:
            p = os.path.join(outdir, f'carved_dell_hdr_{start:08x}.bin')
            with open(p, 'wb') as f:
                f.write(blob)
            carved.append((p, blob))
            log(f'  [carve] Dell HDR zlib @0x{start:X} -> {len(blob):,} bytes')

    # -- Dell PKG (xz) -------------------------------------------------------
    import lzma
    for m in PAT_DELL_PKG.finditer(data):
        start = m.start()
        xz_start = data.find(b'7zXZ', start)
        if xz_start < 0:
            continue
        try:
            blob = lzma.decompress(data[xz_start:])
        except lzma.LZMAError:
            d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            try:
                blob = d.decompress(data[xz_start:])
            except lzma.LZMAError:
                blob = None
        if blob:
            p = os.path.join(outdir, f'carved_dell_pkg_{start:08x}.bin')
            with open(p, 'wb') as f:
                f.write(blob)
            carved.append((p, blob))
            log(f'  [carve] Dell PKG xz @0x{start:X} -> {len(blob):,} bytes')

    # -- generic large zlib streams ------------------------------------------
    seen = set()
    for hdr_magic in (b'\x78\x9C', b'\x78\xDA', b'\x78\x01'):
        for off in find_all(hdr_magic, data):
            if off in seen:
                continue
            seen.add(off)
            d = zlib.decompressobj()
            try:
                blob = d.decompress(data[off:off + 64 * 1024 * 1024])
            except zlib.error:
                continue
            if len(blob) > 512 * 1024:  # only sizeable payloads
                p = os.path.join(outdir, f'carved_zlib_{off:08x}.bin')
                with open(p, 'wb') as f:
                    f.write(blob)
                carved.append((p, blob))
                log(f'  [carve] generic zlib @0x{off:X} -> {len(blob):,} bytes')

    return carved


# --------------------------------------------------------------------------
# Stage 3 — Dell PFS extraction (biosutilities)
# --------------------------------------------------------------------------

def try_pfs(blob: bytes, outdir: str, name: str):
    pfs_root = os.path.join(outdir, f'pfs_{name}')
    os.makedirs(pfs_root, exist_ok=True)
    tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             'tools', 'BIOSUtilities')
    if os.path.isdir(tools_dir):
        sys.path.insert(0, tools_dir)
    try:
        from biosutilities.dell_pfs_extract import DellPfsExtract
    except ImportError:
        log('  [!] biosutilities not available — skipping PFS extraction')
        return False
    try:
        ext = DellPfsExtract(input_object=bytearray(blob), extract_path=pfs_root, padding=8)
        if not ext.check_format():
            return False
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ok = ext.parse_format()
        (open(os.path.join(outdir, f'pfs_{name}.log'), 'w')
         .write(buf.getvalue()))
        log(f'  [PFS] extracted {name} -> {pfs_root}')
        return ok
    except Exception as e:  # noqa: BLE001
        log(f'  [!] PFS extraction failed for {name}: {e}')
        return False


# --------------------------------------------------------------------------
# Stage 4 — UEFI firmware volume parsing (uefi_firmware)
# --------------------------------------------------------------------------

def try_uefi(path: str, outdir: str, name: str):
    uefi_dir = os.path.join(outdir, f'uefi_{name}')
    os.makedirs(uefi_dir, exist_ok=True)
    try:
        from uefi_firmware import AutoParser
    except ImportError:
        log('  [!] uefi_firmware not installed — skipping FV parse')
        return False
    with open(path, 'rb') as f:
        data = f.read()
    try:
        parser = AutoParser(data)
        ftype = parser.type()
    except Exception as e:  # noqa: BLE001
        log(f'  [!] AutoParser failed: {e}')
        return False
    if ftype in ('unknown', None):
        return False
    log(f'  [UEFI] {name}: type={ftype}')
    buf = io.StringIO()
    try:
        fw = parser.parse()
        with contextlib.redirect_stdout(buf):
            fw.showinfo()
    except Exception as e:  # noqa: BLE001
        log(f'  [!] showinfo failed: {e}')
    (open(os.path.join(outdir, f'uefi_{name}.tree.txt'), 'w')
     .write(buf.getvalue()))
    # full extraction via CLI (writes <path>.extracted tree)
    cli = 'uefi-firmware-parser'
    from shutil import which
    if which(cli):
        subprocess.run([cli, '-b', '-e', '-O', uefi_dir, path],
                       capture_output=True, timeout=600)
        log(f'  [UEFI] extracted objects -> {uefi_dir}')
    return True


# --------------------------------------------------------------------------
# Stage 5 — strings & report
# --------------------------------------------------------------------------

def strings_report(data: bytes, outdir: str, label: str):
    hits = {}
    for pat in INTERESTING:
        cnt = len(re.findall(pat, data))
        if cnt:
            hits[pat.decode(errors='replace')] = cnt
    # UTF-16LE strings containing version-ish or model-ish tokens
    utf16 = re.findall(rb'(?:[\x20-\x7E]\x00){6,}', data)
    interesting_utf16 = []
    for s in utf16:
        t = s.decode('utf-16-le', errors='ignore')
        if re.search(r'(?i)optiplex|dell|version|bios|3090|capsule|2\.0\.7', t):
            interesting_utf16.append(t)
    rep = {'binary': label, 'size': len(data),
           'signature_hits': hits,
           'interesting_utf16': interesting_utf16[:200]}
    with open(os.path.join(outdir, f'strings_{label}.json'), 'w') as f:
        json.dump(rep, f, indent=2)
    log(f'  [strings] {label}: {hits}')
    return rep


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    inp = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else (inp + '.analysis')
    os.makedirs(outdir, exist_ok=True)

    with open(inp, 'rb') as f:
        data = f.read()
    log(f'[*] Input: {inp} ({len(data):,} bytes)')
    log(f'[*] SHA-256: ', end='')
    import hashlib
    log(hashlib.sha256(data).hexdigest())
    log(f'[*] Identification: {identify(data)}')

    log('[1] PE metadata / resources')
    carved = pe_report(data, outdir)

    log('[2] Carving compressed streams')
    carved += carve_streams(data, outdir)
    if not carved:
        log('  (no compressed payload carved directly — will scan whole file)')

    log('[3] PFS / UEFI analysis of every candidate blob')
    candidates = [(os.path.basename(p), b) for (p, b) in carved]
    candidates.append(('input', data))
    for name, blob in candidates:
        try_pfs(blob, outdir, name)
        p = os.path.join(outdir, f'blob_{name}')
        if not os.path.exists(p):
            with open(p, 'wb') as f:
                f.write(blob)
        try_uefi(p, outdir, name)
        strings_report(blob, outdir, name)

    log(f'[*] Done. Artifacts in {outdir}/')


if __name__ == '__main__':
    main()
