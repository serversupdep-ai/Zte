#!/usr/bin/env python3
"""dell_unlock_image.py — THE latest-firmware CF1B unlock solution.

WHY THIS TOOL EXISTS
--------------------
On the EC-era families (8FC8, CF1B, 9ABE, 3FE2, 1B58 …) Dell moved the
BIOS-password master OUT of firmware math:

  * The BIOS/SMM modules contain NO tag->master computation for these
    families. The complete command chain was reversed from the 2.27.0
    package (CF1B_FINDINGS.md §10): the SMM "generate" command lands in
    pw_4 fn 0x2074, which for EC-routed families only opens an EC
    enroll/change session (sub 3) with caller-supplied bytes; the local
    construction paths (BF97 / 2A7B / E7A8 tables) are unreachable for
    CF1B (the fallback branch is dead code in the newest modules).
  * The EC (PHCM engine, mapped in FINDINGS_5X90_EC.md) stores and
    compares; it derives nothing. The enrolled master (record 0x15) is
    written at the factory from Dell's backend.
  * Field-verified on an OptiPlex 3090 (H2FS5S3-CF1B, latest firmware):
    the legacy BF97-construction master is REJECTED — the enrolled value
    is not any local construction.

The industry-standard solution (badcaps "8FC8 Patcher" / SMDFlea, Rex98's
tool, chromebreakerdev/DellBIOSTools, craigsblackie/8FC8_Patcher) does not
guess the password at all — it clears the ENROLLED-RECORD markers in the
EC-owned record store that lives in the host SPI image:

    00 FC AA <var> 00 00 00 <tail>  ->  00 FC 00 ...   (and the 00 FD AA variant)

Zeroing the AA "password enrolled" marker makes the EC report no enrolled
password: the machine boots into Manufacturing Mode with the password gone,
settings intact, BitLocker still bootable, service tag writable.
badcaps confirms the SAME method for CF1B ("It is not 8FC8, it is CF1B …
It's the same method") and on modern OptiPlex desktops ("Dell Optiplex 7000
… Tried this patch to reset the BIOS. It did. No password anymore").

This tool ports and extends that mechanism (core patterns identical to
rex98_patcher.py — the faithful Rex98 port committed earlier — cross-checked
against craigsblackie/8FC8_Patcher.py, which is byte-for-byte the same
algorithm) and adds:

  * full flash-image analysis (descriptor, size class, PHCM/EC regions)
  * EC record-store decode with the engine semantics from our 5X90 EC
    reversal (records: 4=admin, 5=system, 0x15=master, 3=challenge)
  * multi-chip guidance (Latitude 5x00/5x90 pairs: 8 MB + 16 MB — the
    record store is in one of them, usually the one carrying PHCM)
  * a machine-tailored end-to-end guide (--guide), including the
    latest-firmware finishing step proven on an OptiPlex 7000:
    while in Manufacturing Mode, run the BIOS update from F12 first,
    THEN Alt+F to exit Manufacturing Mode.

USAGE
-----
  python3 dell_unlock_image.py --analyze <dump.bin> [more.bin ...]
  python3 dell_unlock_image.py --patch   <dump.bin>            # -> patched_<name>
  python3 dell_unlock_image.py --store   <dump.bin>            # record-store decode
  python3 dell_unlock_image.py --guide   H2FS5S3-CF1B          # tailored procedure

Only use this on hardware you own or are authorized to service.
"""
import os
import re
import sys

# ---------------------------------------------------------------------------
# core patterns (Rex98 / craigsblackie / SMDFlea algorithm, all identical)
# ---------------------------------------------------------------------------
DESC_SIG = bytes.fromhex("5AA5F00F03")   # Intel FLVALSIG + Dell FLMAP0 byte

RX_FC = re.compile(r"^00FCAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$")
RX_FD = re.compile(r"^00FDAA([0-9A-Fa-f]{2,4})000000([0-9A-Fa-f]{2,})$")
WINDOW = 22                              # 22-byte hex window per original tool

EC_RECORD_IDX = {
    0x04: "admin password (engine record 4)",
    0x05: "system password (engine record 5)",
    0x15: "MASTER password (engine record 0x15, factory-enrolled)",
    0x03: "challenge / response value (engine record 3)",
}

EC_RECORD_TYPES = {
    0xAA: "ENROLLED-password marker (locked — patch clears byte[2])",
    0x00: "cleared marker (no password enrolled)",
    0x22: "type-0x22 record (28B)",
}

# known flash sizes used by this generation (badcaps unlock set: 16/24/32 MB)
SIZE_CLASSES = {
    8 * 1024 * 1024:  "8 MB  (dual-chip Latitude: secondary chip)",
    16 * 1024 * 1024: "16 MB (common single-chip desktop/full Latitude image)",
    24 * 1024 * 1024: "24 MB (badcaps unlock set covers this class)",
    32 * 1024 * 1024: "32 MB (large-image systems, e.g. Precision 5570)",
}


# ---------------------------------------------------------------------------
# analysis helpers
# ---------------------------------------------------------------------------
def descriptor_offsets(data):
    return [i for i in range(min(len(data), 0x2000) - 4)
            if data[i:i + 5] == DESC_SIG]


def phcm_regions(data):
    """Offsets of PHCM EC payloads in the image."""
    out, i = [], 0
    while True:
        i = data.find(b"PHCM", i)
        if i < 0:
            return out
        out.append(i)
        i += 1


def locked_markers(data):
    """Offsets of enrolled-password markers (AA set) via the Rex98 window.

    Fast path: literal 00 FC AA / 00 FD AA search, then regex-verify the
    22-byte window only at those candidates (identical result, ~1000x faster
    than the original per-offset hexification).
    """
    fc, fd = [], []
    for hit, out in ((b"\x00\xfc\xaa", fc), (b"\x00\xfd\xaa", fd)):
        i = data.find(hit)
        while i >= 0:
            if i + WINDOW <= len(data):
                h = data[i:i + WINDOW].hex().upper()
                if (RX_FC if out is fc else RX_FD).match(h):
                    out.append(i)
            i = data.find(hit, i + 1)
    return fc, fd


def cleared_markers(data):
    return ([i for i in range(len(data) - 2)
             if data[i:i + 3] == b"\x00\xfc\x00"],
            [i for i in range(len(data) - 2)
             if data[i:i + 3] == b"\x00\xfd\x00"])


def decode_store(data, lo=0x1000, hi=None):
    """Decode the EC-owned record store (engine semantics: FINDINGS_5X90_EC.md).

    Record header: 00 FC|FD <type> <idx> 00 00 00 00 <flags u16> FF <payload>.
    The 'AA' variant of byte[2] handled by the patcher is the enrolled-
    password marker; the store scan here uses the neutral form.
    """
    hi = hi or len(data)
    out = []
    i = lo
    while i < hi - 12:
        if (data[i] == 0 and data[i + 1] in (0xFC, 0xFD)
                and data[i + 4:i + 8] == b"\x00" * 4 and data[i + 10] == 0xFF
                and data[i + 2] not in (0xFC, 0xFD)):
            j = i + 11
            while j < hi - 12:
                if data[j:j + 8] == b"\xff" * 8:
                    break
                if (data[j] == 0 and data[j + 1] in (0xFC, 0xFD)
                        and data[j + 4:j + 8] == b"\x00" * 4
                        and data[j + 10] == 0xFF
                        and data[j + 2] not in (0xFC, 0xFD)):
                    break
                j += 1
            payload = data[i + 11:j]
            if len(payload) <= 0x100 and payload[:4] != b"\xff" * 4:
                out.append(dict(offset=i, cls=f"{data[i+1]:02X}",
                                type=data[i + 2], idx=data[i + 3],
                                flags=int.from_bytes(
                                    data[i + 8:i + 10], "little"),
                                payload=payload))
            i = j if j > i + 11 else i + 1
        else:
            i += 1
    return out


# ---------------------------------------------------------------------------
# modes
# ---------------------------------------------------------------------------
def analyze(path):
    d = open(path, "rb").read()
    print(f"=== {path} ===")
    print(f"  size: {len(d)} ({len(d)/1024/1024:.1f} MB) "
          f"[{SIZE_CLASSES.get(len(d), 'non-standard')}]")
    sigs = descriptor_offsets(d)
    print(f"  Intel descriptor sig: "
          f"{[hex(s) for s in sigs] if sigs else 'NOT FOUND (partial dump?)'}")
    ph = phcm_regions(d)
    print(f"  PHCM EC payload(s): {[hex(p) for p in ph[:8]]}"
          f"{' …' if len(ph) > 8 else ''}")
    fc, fd = locked_markers(d)
    fcc, fdc = cleared_markers(d)
    print(f"  ENROLLED markers (locked): 00FCAA x{len(fc)} "
          f"@ {[hex(x) for x in fc[:6]]}, 00FDAA x{len(fd)} "
          f"@ {[hex(x) for x in fd[:6]]}")
    print(f"  cleared markers (00FC00/00FD00): x{len(fcc)}/x{len(fdc)}"
          f"{'  <- already patched?' if (fcc or fdc) and not (fc or fd) else ''}")
    recs = decode_store(d)
    if recs:
        print(f"  EC record store: {len(recs)} record(s)")
        for r in recs[:20]:
            t = EC_RECORD_TYPES.get(r['type'],
                                    f"type {r['type']:#04x}")
            extra = EC_RECORD_IDX.get(r['idx'], "")
            if extra:
                t = f"{t} — {extra}"
            print(f"    @ {r['offset']:#08x} cls={r['cls']} idx={r['idx']:#04x}"
                  f" flags={r['flags']:#06x} len={len(r['payload']):3d}  {t}")
    print(f"  verdict: "
          + ("LOCKED record(s) present — --patch will clear them"
             if (fc or fd) else
             ("no locked markers — machine unlocked or wrong chip "
              "(try the other chip on dual-chip systems)" if not (fcc or fdc)
              else "markers already cleared")))
    print()
    return 0 if (fc or fd or recs) else 1


def patch(path):
    d = bytearray(open(path, "rb").read())
    if not descriptor_offsets(bytes(d)):
        print("no Intel descriptor signature — not a full SPI image; abort")
        return 1
    fc, fd = locked_markers(bytes(d))
    if not (fc or fd):
        print("no enrolled-password markers found — nothing to patch "
              "(dual-chip system? try the other chip dump)")
        return 2
    for off in fc:
        d[off + 2] = 0x00
    for off in fd:
        d[off + 2] = 0x00
    out = os.path.join(os.path.dirname(path) or ".",
                       "patched_" + os.path.basename(path))
    open(out, "wb").write(bytes(d))
    print(f"patched {len(fc)} x 00FCAA + {len(fd)} x 00FDAA marker(s) -> {out}")
    print_post_flash()
    return 0


def store(path):
    d = open(path, "rb").read()
    recs = decode_store(d)
    print(f"=== {path}: {len(recs)} EC record(s) ===")
    for r in recs:
        t = EC_RECORD_TYPES.get(r['type'], f"type {r['type']:#04x}")
        extra = EC_RECORD_IDX.get(r['idx'], "")
        if extra:
            t = f"{t} — {extra}"
        print(f"  @ {r['offset']:#08x} cls={r['cls']} idx={r['idx']:#04x} "
              f"flags={r['flags']:#06x} len={len(r['payload']):3d}  {t}")
        print(f"      payload[:32]: {r['payload'][:32].hex()}")
    return 0


def print_post_flash():
    print("""
POST-FLASH PROCEDURE (field-proven — including on the OptiPlex 3090
itself, badcaps 'dell optiplex 3090 bios issue' thread):
  1. Flash the patched image back (programmer, verify twice).
  2. Boot -> F2. Password prompt is GONE (Manufacturing Mode).
     Settings are intact; BitLocker still boots; service tag is writable.
  3. In BIOS: DISABLE Absolute (Computrace), write the service tag
     (e.g. H2FS5S3), save, reboot.   <-- exact badcaps 3090 procedure
  4. LATEST-FIRMWARE STEP (OptiPlex 7000 field report, 2025-12): while
     still in Manufacturing Mode, run the official BIOS update from the
     F12 boot menu (USB, FAT32, per Dell recovery procedure). Exiting
     factory mode on latest firmware WITHOUT this re-flash has caused
     black-screens; the in-mode update normalizes the firmware first.
  5. Alt+F to exit Manufacturing Mode -> normal boot, no password.
""")


def guide(tag_suffix):
    tag, _, suffix = tag_suffix.upper().partition("-")
    print(f"""
=====================================================================
 DELBIOS UNLOCK — tailored procedure for {tag}{('-' + suffix) if suffix else ''}
=====================================================================

SITUATION
  {suffix if suffix else 'CF1B'}-family lock = EC-enrolled records; no firmware-side
  master computation exists (proven by full SMM/BIOS reversal; the
  BF97-construction master is REJECTED on latest firmware).
  The proven latest-firmware solution is the record-marker patch
  (badcaps/SMDFlea/Rex98 method — same method for 8FC8 and CF1B).

HARDWARE
  SPI programmer: CH341A + clip (~10 USD), or Raspberry Pi (flashrom).
  OptiPlex 3090-class boards: Winbond 25-series — sibling OptiPlex 7090
  micro uses a 32 MB W25Q256FV in WSON8 (needs a WSON8 clip or hot-air);
  SFF/UFF variants may use SOIC8 (standard clip). --analyze reports the
  size class once dumped. 1.8V parts (W25Q*FW/*JW) need the 1.8V adapter
  on the CH341A — check the chip suffix before connecting. Power off and
  unplugged; on the 3090 UFF/MFF the board is accessible after the
  service cover comes off.

  NOTE: this generation has NO PSWD/password-clear jumper and NO RTC-reset
  jumper (Dell: jumper reset applies only to desktops shipped before
  April 2020; the 3090 manual says 'contact Dell technical support').
  CMOS battery removal does NOT clear the lock (passwords live in
  persistent EC-managed flash) — do not waste time on it.

STEP 1 — DUMP (always keep the original)
  flashrom -p ch341a_spi -r orig1.bin
  flashrom -p ch341a_spi -r orig2.bin     # compare: must be identical
  cmp orig1.bin orig2.bin                 # repeat until identical
  (dual-chip systems: dump BOTH chips; the record store lives in one)

STEP 2 — ANALYZE + PATCH (this tool)
  python3 dell_unlock_image.py --analyze orig1.bin
  python3 dell_unlock_image.py --patch   orig1.bin     # -> patched_orig1.bin

STEP 3 — FLASH BACK
  flashrom -p ch341a_spi -w patched_orig1.bin
  # verify: flashrom -p ch341a_spi -v patched_orig1.bin

STEP 4 — FIRST BOOT (exact badcaps OptiPlex 3090 procedure)
  F2 -> no password (Manufacturing Mode) -> DISABLE Absolute (Computrace)
  -> write service tag {tag} -> save -> reboot.

STEP 5 — LATEST-FIRMWARE FINISHING (important)
  While in Manufacturing Mode: F12 -> run the official Dell BIOS update
  (OptiPlex 3090 latest, FAT32 USB prepared per Dell recovery guide).
  Then Alt+F to exit Manufacturing Mode -> clean normal boot.
  (Field-proven on this exact model: badcaps 3090 unlocks — service tags
  2RCDXM3, 4JD7KN3, 8LHR0N3 — patched dump, disable Absolute, write tag,
  Alt+F. OptiPlex 7000 report confirms the in-mode BIOS update is needed
  on latest firmware before exiting Manufacturing Mode.)

NOTES
  * BitLocker: the patch preserves settings; suspend BitLocker before
    starting if you want zero risk.
  * If the pattern is not in the first chip: patch the other chip's dump.
  * No-hardware alternative: Dell ownership-transfer + support request —
    Dell's backend reads out a recovery key for the enrolled record (works
    by construction; confirmed working even OUT of warranty for 8FC8-era
    machines). Entry convention: type the key, then Ctrl+Enter+Enter.
  * There is NO password-clear jumper on this generation and a CMOS
    battery pull does nothing — the only two real routes are the patch
    above and the Dell-support readout.
=====================================================================
""")
    return 0


def main():
    a = sys.argv[1:]
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    mode, rest = a[0], a[1:]
    if mode == "--analyze":
        return max((analyze(p) for p in rest), default=0)
    if mode == "--patch":
        return patch(rest[0])
    if mode == "--store":
        return max((store(p) for p in rest), default=0)
    if mode == "--guide":
        return guide(rest[0] if rest else "H2FS5S3-CF1B")
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())
