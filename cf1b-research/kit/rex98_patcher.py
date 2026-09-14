#!/usr/bin/env python3
"""rex98_patcher.py — faithful Python reimplementation of Rex98's Dell 8FC8
BIOS password patcher (Rex_8FC8_patcher.exe), reverse-engineered from the
tool itself (REPORT §13.10).

The original is a VB.NET console app packed inside a 64 MB native
bootstrapper (extracted: overlay @0x936E00, embedded .NET PE at +0x200,
class _8FC8_Patcher.Module8FC8). Its algorithm, recovered from the CIL:

    bytes  = File.ReadAllBytes(<locked bios.bin>)
    sig    = hex2bytes('5AA5F00F03')      # Intel flash-descriptor signature
                                          # 5A A5 F0 0F + Dell FLMAP0 byte 03
    require an offset where sig matches    ("intel signature")
    rx1    = '^00FCAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$'
    repl1  = hex2bytes('00FC00')           # -> zero the AA marker byte
    for off in PatternAt(bytes, rx1):      # 22-byte window at every offset,
        bytes[off:off+3] = repl1           # hexified, regex-tested
    if no hit:
        rx2   = '^00FDAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$'
        repl2 = hex2bytes('00FD00')
        same again
    save as patched_<name>

Semantics: the Dell NVRAM password record for the 8FC8 family starts with
bytes `00 FC AA <1-2 var> 00 00 00 <tail>` (or the 00 FD AA variant); the
third byte AA marks "password enrolled". Zeroing that byte makes the BIOS
treat the machine as having no BIOS password. This is the patch route; the
§13 crack computes the password instead.

Usage:
  python3 rex98_patcher.py --detect <dump.bin> [...]   # report records
  python3 rex98_patcher.py --patch <locked.bin>        # write patched_<name>
  python3 rex98_patcher.py --store <dump.bin> [...]    # decode EC record store
"""
import os
import re
import sys

SIG = bytes.fromhex("5AA5F00F03")
RX1 = re.compile(r"^00FCAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$")
RX2 = re.compile(r"^00FDAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$")
WINDOW = 22          # len(rx string) // 2 bytes, per the original tool


def pattern_at(data, rx, window=WINDOW):
    """Faithful port of Module8FC8.PatternAt: yield offsets whose `window`
    -byte hex form matches the anchored regex."""
    out = []
    for i in range(len(data) - window + 1):
        h = data[i:i + window].hex().upper()
        if rx.match(h):
            out.append(i)
    return out


def decode_store(data, lo=0x1000, hi=None):
    """Decode the EC-owned record store: 00 FC|FD <type> <idx> 00000000
    <flags u16> FF <payload>. Returns list of dicts. Records are packed
    (28-byte type-0x22, 60-byte type-0xAA/0x00) — we scan for headers."""
    hi = hi or len(data)
    out = []
    i = lo
    bad_types = (0xFC, 0xFD)
    while i < hi - 12:
        if data[i] == 0 and data[i + 1] in (0xFC, 0xFD) \
                and data[i + 4:i + 8] == b"\x00" * 4 and data[i + 10] == 0xFF \
                and data[i + 2] not in bad_types:
            # plausible header; bound payload by next header or 0xFF padding
            j = i + 11
            while j < hi - 12:
                if data[j:j + 8] == b"\xff" * 8:
                    break
                if data[j] == 0 and data[j + 1] in (0xFC, 0xFD) \
                        and data[j + 4:j + 8] == b"\x00" * 4 \
                        and data[j + 10] == 0xFF and data[j + 2] not in bad_types:
                    break
                j += 1
            payload = data[i + 11:j]
            if len(payload) <= 0x100 and payload[:4] != b"\xff" * 4:
                out.append(dict(offset=i, cls=f"{data[i+1]:02X}", type=data[i + 2],
                                idx=data[i + 3], flags=int.from_bytes(
                                    data[i + 8:i + 10], "little"),
                                payload=payload))
            i = j if j > i + 11 else i + 1
        else:
            i += 1
    return out


def hex2bytes(h):
    if len(h) % 2:
        raise ValueError(f"odd hex length: {h}")
    return bytes.fromhex(h)


def detect(data):
    """Return (sig_offsets, fc_locked, fd_locked, fc_cleared, fd_cleared)."""
    sigs = [i for i in range(len(data) - 4) if data[i:i + 5] == SIG]
    fc_locked = pattern_at(data, RX1)
    fd_locked = pattern_at(data, RX2)
    fc_cleared = [i for i in range(len(data) - WINDOW + 1)
                  if data[i:i + 3] == b"\x00\xfc\x00"]
    fd_cleared = [i for i in range(len(data) - WINDOW + 1)
                  if data[i:i + 3] == b"\x00\xfd\x00"]
    return sigs, fc_locked, fd_locked, fc_cleared, fd_cleared


def patch(path):
    data = bytearray(open(path, "rb").read())
    sigs, fc, fd, _, _ = detect(bytes(data))
    if not sigs:
        print("wa nakit-an ang intel signature (no Intel descriptor) — abort")
        return 1
    print(f"intel signature at {[hex(s) for s in sigs[:4]]}")
    hits = fc or fd
    rx_name = "FC" if fc else ("FD" if fd else None)
    if rx_name:
        for off in hits:
            data[off + 2] = 0x00          # zero the AA marker
        out = os.path.join(os.path.dirname(path),
                           "patched_" + os.path.basename(path))
        open(out, "wb").write(bytes(data))
        print(f"patched {len(hits)} {rx_name} record(s) at "
              f"{[hex(o) for o in hits]} -> {out}")
        return 0
    print("wa na patch...ky wa makita ang pattern (no password record)")
    return 2


def main():
    args = sys.argv[1:]
    if not args or args[0] not in ("--detect", "--patch", "--store"):
        print(__doc__)
        return 0
    mode, paths = args[0], args[1:]
    if mode == "--patch":
        return patch(paths[0])
    if mode == "--store":
        for p in paths:
            d = open(p, "rb").read()
            recs = decode_store(d, 0x1000, 0x101000)   # EC-owned hole
            print(f"=== {os.path.basename(p)}: {len(recs)} records ===")
            types = {}
            for r in recs:
                types.setdefault(f"{r['cls']}/{r['type']:02X}", 0)
                types[f"{r['cls']}/{r['type']:02X}"] += 1
            print("  types:", {k: v for k, v in sorted(types.items())})
            for r in recs:
                mark = " <== PASSWORD RECORD" if r["type"] == 0xAA else ""
                print(f"    @{r['offset']:#09x} {r['cls']} type={r['type']:02X} "
                      f"idx={r['idx']:02X} flags={r['flags']:04X} "
                      f"payload={len(r['payload'])}B{mark}")
                if r["type"] == 0xAA and len(r["payload"]) <= 128:
                    print(f"        sealed: {r['payload'].hex()}")
        return 0
    for p in paths:
        d = open(p, "rb").read()
        sigs, fc, fd, fcc, fdc = detect(d)
        print(f"=== {os.path.basename(p)} ({len(d):,} B) ===")
        print(f"  intel sig offsets : {[hex(s) for s in sigs[:6]]}"
              f"{' ...' if len(sigs) > 6 else ''}")
        print(f"  LOCKED  records   : FC={[hex(o) for o in fc]} FD={[hex(o) for o in fd]}")
        print(f"  cleared FC00/FD00 : {len(fcc)} / {len(fdc)} raw marker hits")
        for o in fc + fd:
            print(f"    record @ {o:#x}: {d[o:o+22].hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
