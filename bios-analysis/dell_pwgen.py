#!/usr/bin/env python3
"""dell_pwgen.py — PW-gen for the Dell CF1B generation (pwgen-for-bios style).

Generates the BIOS master password for machines showing the EC-routed
suffixes  -CF1B  -1B58  -9ABE  -3FE2   (OptiPlex 3080/3090/5080/5090/7080/
7090/XE4, Latitude 5300/5400/5500, Precision 3540, ...).

BASIS (CF1B_FINDINGS.md, REPORT.md §9.6, executed firmware — no invented
algorithm):
  * The machine's own pw-module keygen API, executed under unicorn x86-64,
    generates the master for these families via its fallback construction
    (the family constant is HARDCODED — all four suffixes yield the SAME
    master per service tag; proven by execution).
  * Proven byte-identical across INDEPENDENT module builds: OptiPlex 3090
    2.0.7 pw_4 (API @0x926C) and Latitude 5400/5500/Precision 3540 1.43.1
    pw_11 (API @0x927C) — 6/6 tags identical outputs, plus the pure-Python
    port matches 6/6 (dell_pwgen.py --selftest).
  * The new-era module (43008 bytes, byte-identical in 3090 2.27.0/2.30.0,
    3080 2.35.0, 5080/7080/5480/3280/7780, 5X00 pw_12) still ships the same
    fallback (execution-proven via forced branch, pw_fw_exec.py).
  * 8FC8 is NOT covered (its table entry is a stub -> EFI_INVALID_PARAMETER;
    the 8FC8 algorithm lives EC-side only).

USAGE
    python3 dell_pwgen.py 9LNT2Z2-CF1B           # pwgen-style: TAG-SUFFIX
    python3 dell_pwgen.py 9LNT2Z2 CF1B
    python3 dell_pwgen.py 9LNT2Z2-CF1B --firmware \
        collected/Latitude_5X00_Precision_3540_1.43.1/pw_11_42496.efi
        # generate by EXECUTING the real firmware module (unicorn) instead
        # of the pure-Python port
    python3 dell_pwgen.py --batch tags.txt       # one TAG[-SUFFIX] per line
    python3 dell_pwgen.py --selftest             # firmware cross-validation

EVIDENCE STATUS: construction = executed-firmware-validated (two independent
module builds, byte-identical). Field validation: the H2FS5S3-CF1B master
(shzNyjGRzRN2LLzL) delivered earlier from the same path; the example tags in
--selftest come from public help threads (Reddit r/Dell) and are computed,
not yet machine-verified. For machines you own or are authorized to service.
"""
import re
import struct
import sys

sys.path.insert(0, ".")

from dell_keygen import keygen_cf1b, keygen_cf1b_alt_fnA, keygen_e7a8

# service tags publicly documented as locked -CF1B machines (Reddit r/Dell
# thread "Bios password reset", Aug-Sep 2025) — used as reproducible examples
DOCUMENTED_TAGS = ["9LNT2Z2", "8XKP5Y2", "4J5SCF4", "3BJJ9C3", "9B1N0R3",
                   "H2FS5S3"]

EC_ROUTED_FAMILIES = {"CF1B": 0xCF1B, "1B58": 0x1B58, "9ABE": 0x9ABE,
                      "3FE2": 0x3FE2}


# ----------------------------------------------------------------------
# firmware-execution backend (optional; requires unicorn)
# ----------------------------------------------------------------------
def locate_api(path):
    """Auto-locate the modern keygen API in a 42496/43008-class pw module.

    Returns (api_rva, era) with era in {"old", "new"}:
      old: lookup sentinel `mov eax,0xFF; ret`  -> CF1B generates naturally
      new: sentinel 0xFFFF                      -> natural = INVALID_PARAM,
                                                   same fallback via je->jmp
    """
    d = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e_lfanew + 6)[0]
    optsz = struct.unpack_from("<H", d, e_lfanew + 20)[0]
    so = e_lfanew + 24 + optsz
    secs = []
    for i in range(nsec):
        off = so + i * 40
        nm = d[off:off + 8].rstrip(b"\0").decode(errors="replace")
        vsz, va, rsz, ro = struct.unpack_from("<IIII", d, off + 8)
        secs.append((nm, va, vsz, ro, rsz))
    text = next(s for s in secs if s[0] == ".text")
    tnm, tva, tvsz, tro, trsz = text
    code = d[tro:tro + trsz]

    PROLOG = rb"\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10"
    CMP_RAX_FF = rb"\x48\x3d\xff\x00\x00\x00"          # in the API, both eras

    for m in re.finditer(PROLOG, code):
        base = m.start()
        # within the next 0x40 bytes: a call, then cmp rax,0xff
        window = code[base:base + 0x40]
        c = re.search(rb"\xe8....\x48\x3d\xff\x00\x00\x00", window, re.DOTALL)
        if not c:
            continue
        api = tva + base
        # resolve the lookup target and determine the era by its sentinel
        rel = struct.unpack_from("<i", window, c.start() + 1)[0]
        lookup = api + c.start() + 5 + rel
        lo = lookup - tva
        body = code[lo:lo + 0x60]
        if b"\xb8\xff\x00\x00\x00\xc3" in body:         # mov eax,0xFF; ret
            return api, "old"
        if b"\x49\x8b\xc1\xc3" in body:                 # mov rax,r9; ret
            return api, "new"
    return None, None


def generate_firmware(tag, suffix, module_path):
    """Generate by EXECUTING the real pw module (unicorn)."""
    from pw_fw_exec import Mod
    api, era = locate_api(module_path)
    if api is None:
        raise RuntimeError(
            f"could not locate the keygen API in {module_path} "
            f"(module may be a shape without local generation, e.g. "
            f"Latitude 5300 pw_7 / 38912-class)")
    m = Mod(module_path, api)
    family = EC_ROUTED_FAMILIES.get(suffix.upper(), 0xCF1B)
    st, out = m.call_api(tag.upper().encode(), 0x40, family, 1,
                         force_fallback=(era == "new"))
    if st != 0 or not out:
        return None, st
    return out[:16].decode("latin-1"), st


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def generate(tag, suffix="CF1B", firmware=None):
    suffix = suffix.upper()
    if firmware:
        return generate_firmware(tag, suffix, firmware)
    return keygen_cf1b(tag.upper(), suffix, verbose=False), None


def report(tag, suffix="CF1B", firmware=None):
    print(f"Service tag : {tag.upper()}")
    print(f"Suffix      : -{suffix.upper()}")
    if suffix.upper() in EC_ROUTED_FAMILIES and suffix.upper() != "CF1B":
        print(f"(EC-routed sibling of CF1B -- same master per tag)")
    pw, st = generate(tag, suffix, firmware)
    src = "EXECUTED FIRMWARE" if firmware else "pure-Python port (firmware-validated)"
    print(f"\nMaster password ({src}):\n")
    print(f"    {pw}")
    if st is not None:
        print(f"    [module status {st:#x}]")
    print("\nAlternates (only if the primary is not accepted):")
    print(f"    [fnA-legacy] {keygen_cf1b_alt_fnA(tag.upper())}")
    for i, p in enumerate(keygen_e7a8(tag.upper())):
        print(f"    [E7A8 #{i+1}]     {p}")
    return pw


def selftest():
    import io
    import contextlib
    ok = True

    # 1) pure-Python across the documented tags
    print("== pure-Python generation, publicly documented -CF1B machines ==")
    for tag in DOCUMENTED_TAGS:
        with contextlib.redirect_stdout(io.StringIO()):
            pw = keygen_cf1b(tag, "CF1B", verbose=False)
        print(f"  {tag}-CF1B -> {pw}")
    ref = {t: keygen_cf1b(t, "CF1B", verbose=False) for t in DOCUMENTED_TAGS}
    assert ref["H2FS5S3"] == "shzNyjGRzRN2LLzL", "primary regression!"
    print("  H2FS5S3 == shzNyjGRzRN2LLzL (delivered master): OK")

    # 2) firmware execution cross-check (if unicorn available)
    try:
        from pw_fw_exec import Mod
    except ImportError:
        print("\nunicorn not installed -- skipping firmware cross-check")
        print("RESULT: PASS (pure-Python only)")
        return 0
    print("\n== executed-firmware cross-check (2 independent module builds) ==")
    m3090 = Mod("collected/OptiPlex_3090_2.0.7/pw_4_42496.efi", 0x926C)
    m5x00 = Mod("collected/Latitude_5X00_Precision_3540_1.43.1/pw_11_42496.efi",
                0x927C)
    for tag in DOCUMENTED_TAGS:
        st1, o1 = m3090.call_api(tag.encode(), 0x40, 0xCF1B, 1)
        st2, o2 = m5x00.call_api(tag.encode(), 0x40, 0xCF1B, 1)
        py = ref[tag]
        good = (st1 == 0 and st2 == 0 and o1[:16].decode("latin-1") == py
                and o2[:16].decode("latin-1") == py)
        ok &= good
        print(f"  {tag}: 3090/2.0.7 {o1[:16].decode('latin-1')}  "
              f"5X00/1.43.1 {o2[:16].decode('latin-1')}  "
              f"py {py}  {'MATCH' if good else 'MISMATCH'}")

    # 3) sibling-family equality + 8FC8 refusal (structure assertion)
    st, o = m3090.call_api(b"9LNT2Z2", 0x40, 0x1B58, 1)
    sib = o[:16].decode("latin-1")
    good = st == 0 and sib == ref["9LNT2Z2"]
    for fam in (0x9ABE, 0x3FE2):
        st, o = m3090.call_api(b"9LNT2Z2", 0x40, fam, 1)
        good &= (st == 0 and o[:16].decode("latin-1") == ref["9LNT2Z2"])
    st8, _ = m3090.call_api(b"9LNT2Z2", 0x40, 0x8FC8, 1)
    good &= (st8 == 0x8000000000000002)
    ok &= good
    print(f"  siblings 1B58/9ABE/3FE2 == CF1B master, 8FC8 refuses: "
          f"{'OK' if good else 'FAIL'}")

    # 4) --firmware auto-location
    api, era = locate_api(
        "collected/Latitude_5X00_Precision_3540_1.43.1/pw_11_42496.efi")
    good = (api == 0x927C and era == "old")
    api2, era2 = locate_api(
        "collected/OptiPlex_3090_2.0.7/pw_4_42496.efi")
    good &= (api2 == 0x926C and era2 == "old")
    ok &= good
    print(f"  API auto-location (5X00 pw_11 @0x927C, 3090 2.0.7 @0x926C): "
          f"{'OK' if good else 'FAIL'}")

    print("\nRESULT:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("--selftest", "-t"):
        return selftest()
    if args[0] == "--batch":
        fw = None
        if "--firmware" in args:
            fw = args[args.index("--firmware") + 1]
        for line in open(args[1]):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "-" in line[:12]:
                tag, suffix = line.split("-", 1)
            else:
                tag, suffix = line, "CF1B"
            pw, _ = generate(tag, suffix[-4:].upper(), fw)
            print(f"{tag}-{suffix[-4:].upper()}: {pw}")
        return 0
    # positional parsing with --firmware <path> extracted first
    fw = None
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--firmware" and i + 1 < len(args):
            fw = args[i + 1]
            i += 2
        else:
            positional.append(args[i])
            i += 1
    if len(positional) == 1 and "-" in positional[0][:12]:
        tag, suffix = positional[0].split("-", 1)
    elif len(positional) >= 2:
        tag, suffix = positional[0], positional[1]
    else:
        tag, suffix = positional[0], "CF1B"
    tag = tag.strip().upper()
    if not re.fullmatch(r"[0-9A-Z]{4,11}", tag):
        print(f"invalid service tag: {tag!r}", file=sys.stderr)
        return 1
    report(tag, suffix[-4:].upper(), fw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
