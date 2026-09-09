#!/usr/bin/env python3
"""Extract Dell password-derivation modules from Dell BIOS executables.

Looks for the password modules (identified by the E7A8 alphabet marker
'Q92G0drk' or an {8FC8,E7A8} family-dispatch table), carves their PE images,
decodes the family dispatch tables, and reports everything.

Usage: extract_pw_modules.py <bios.exe> [<bios.exe> ...]
Writes pw_mods/<tag>_pw<n>.efi plus a report to stdout.
"""
import os
import re
import sys
import zlib
import struct
import glob

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from uefi_firmware import AutoParser  # noqa: E402


def walk(obj, sink):
    for d in obj.objects:
        content = b''
        for attr in ('_data', 'data', 'content', '_Content'):
            v = getattr(d, attr, None)
            if isinstance(v, (bytes, bytearray)) and v:
                content = bytes(v)
                break
        if content:
            sink.append(content)
        try:
            walk(d, sink)
        except Exception:
            pass


def find_dub(data):
    """Find the zlib stream that decompresses to the DellUpdateBinary (PFS)."""
    i = 0
    n = len(data)
    while True:
        j = data.find(b'x\x9c', i)
        if j < 0:
            return None
        try:
            d = zlib.decompressobj().decompress(data[j:])
            if b'PFS' in d[:0x10000] and len(d) > 1000000:
                return d
        except Exception:
            pass
        i = j + 1
        if i >= n:
            return None


def carve_pe(c, log):
    mz = c.find(b'MZ')
    if mz < 0:
        return None
    try:
        lf = struct.unpack_from('<I', c, mz + 0x3c)[0]
        if not (0 < lf < 0x400) or c[mz + lf:mz + lf + 4] != b'PE\x00\x00':
            return None
        nsec = struct.unpack_from('<H', c, mz + lf + 6)[0]
        optsz = struct.unpack_from('<H', c, mz + lf + 20)[0]
        secbase = mz + lf + 24 + optsz
        end = 0
        for k in range(nsec):
            so = secbase + k * 40
            rawsz, rawptr = struct.unpack_from('<II', c, so + 16)
            end = max(end, rawptr + rawsz)
        pe = c[mz:mz + end]
        return pe if len(pe) > 8000 else None
    except Exception:
        return None


def dispatch_tables(pe):
    out = []
    for off in range(0, len(pe) - 72, 8):
        if pe[off:off + 2] == b'\xc8\x8f' and pe[off + 2:off + 4] == b'\x00\x00':
            j, entries = 0, []
            while j < 8:
                e = off + j * 24
                fam = struct.unpack('<H', pe[e:e + 2])[0]
                if fam == 0xFFFF:
                    entries.append('END')
                    break
                d8 = struct.unpack('<Q', pe[e + 8:e + 16])[0]
                a16 = struct.unpack('<Q', pe[e + 16:e + 24])[0]
                entries.append('%04X(desc=0x%x,alpha=0x%x)' % (fam, d8, a16))
                j += 1
            if len(entries) > 1:
                out.append((hex(off), entries))
    return out


def process(exe_path, tag, log):
    log('--- %s: %s' % (tag, exe_path))
    data = open(exe_path, 'rb').read()
    dub = find_dub(data)
    if not dub:
        log('  no PFS blob found')
        return
    log('  DellUpdateBinary: %d bytes' % len(dub))
    f = AutoParser(dub).parse()
    if not f:
        log('  parse fail')
        return
    sink = []
    walk(f, sink)
    log('  objects: %d' % len(sink))
    sysbios = None
    for c in sink:
        if len(c) > 15000000 and c.find(b'_FVH') >= 0:
            sysbios = c
            break
    if sysbios is None:
        for c in sink:
            if 15000000 < len(c) < 18000000:
                sysbios = c
                break
    if sysbios is None:
        log('  no system bios payload')
        return
    log('  system bios: %d bytes' % len(sysbios))
    fb = AutoParser(sysbios).parse()
    if not fb:
        log('  bios parse fail')
        return
    sink2 = []
    walk(fb, sink2)
    log('  bios objects: %d' % len(sink2))
    os.makedirs('pw_mods', exist_ok=True)
    n = 0
    seen = set()
    for c in sink2:
        if b'Q92G0drk' not in c and not (b'\xc8\x8f\x00\x00' in c and b'\xa8\xe7\x00\x00' in c):
            continue
        pe = carve_pe(c, log)
        if pe is None or hash(pe) in seen:
            continue
        seen.add(hash(pe))
        fn = 'pw_mods/%s_pw%d.efi' % (tag, n)
        open(fn, 'wb').write(pe)
        tabs = dispatch_tables(pe)
        log('  SAVED %s (%d B) tables=%s' % (fn, len(pe), tabs))
        n += 1
    log('  pw modules saved: %d' % n)


def main():
    exes = []
    for a in sys.argv[1:]:
        exes.extend(glob.glob(a))
    for exe in sorted(exes):
        tag = os.path.basename(exe).replace('.exe', '').replace(' ', '_')[:24]
        try:
            process(exe, tag, print)
        except Exception as e:
            print('  ERROR %s' % e)


if __name__ == '__main__':
    main()
