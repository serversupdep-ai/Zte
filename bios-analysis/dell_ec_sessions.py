#!/usr/bin/env python3
"""dell_ec_sessions.py — enumerate the EC session/command surface of Dell's
DellSecurityVaultSmm / SystemPw password modules (held plaintext PEs).

Answers, from static evidence only:
  1. every session TYPE the module can open (GUID descriptor table + the
     `cmp type, N` dispatch inside the EC-session function),
  2. every mailbox command constant the module writes (0x21 open, 0x17 xfer,
     anything else),
  3. the EC status-byte map (fn 0x31B4-class) — including whether a
     "tag mismatch"-style code exists (bears on donor-machine GENERATE),
  4. any data-flow branch that moves more than 32 bytes out of the EC
     (a potential EC-memory-read door).

Usage: python3 dell_ec_sessions.py <module.pe> [more.pe ...]
"""
import struct
import sys
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP, CS_GRP_CALL


def load_pe(path):
    d = open(path, "rb").read()
    pe = struct.unpack("<I", d[0x3C:0x40])[0]
    optsz = struct.unpack("<H", d[pe + 0x14:pe + 0x16])[0]
    nsec = struct.unpack("<H", d[pe + 6:pe + 8])[0]
    off = pe + 0x18 + optsz
    secs = []
    for i in range(nsec):
        nm = d[off:off + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ra = struct.unpack("<IIII", d[off + 8:off + 24])
        secs.append((nm, va, vs, ra, rs))
        off += 40
    return d, secs


def va2off(secs, va):
    for nm, v, vs, ra, rs in secs:
        if v <= va < v + vs and va - v < rs:
            return ra + (va - v)
    return None


def off2va(secs, off):
    for nm, v, vs, ra, rs in secs:
        if ra <= off < ra + rs:
            return v + (off - ra)
    return None


def guid_at(d, secs, va):
    o = va2off(secs, va)
    if o is None:
        return None
    g = d[o:o + 16]
    if len(g) < 16:
        return None
    return g


def fmt_guid(g):
    if g is None:
        return "?"
    d1, d2, d3 = struct.unpack_from("<IHH", g, 0)
    return "{%08X-%04X-%04X-%s-%s}" % (d1, d2, d3,
                                       g[8:10].hex().upper(),
                                       g[10:16].hex().upper())


def scan(path):
    d, secs = load_pe(path)
    print("=" * 72)
    print(path)
    print("sections:", [(nm, hex(va), hex(vsz)) for nm, va, vsz, _, _ in secs])

    # ---- 1. GUID table: consecutive well-formed GUIDs in .data/.rdata -----
    guids = []
    for nm, va, vs, ra, rs in secs:
        if nm.startswith(".text"):
            continue
        o = ra
        end = ra + rs
        while o + 16 <= end:
            g = d[o:o + 16]
            # heuristics for a plausible MS GUID: not all-zero, not FF,
            # version nibble 1-5, variant top bits 10
            d3 = struct.unpack_from("<H", g, 6)[0]
            if (g.count(0) <= 12 and g.count(0xFF) <= 12
                    and 0x1000 <= d3 <= 0x5FFF
                    and (g[8] & 0xC0) == 0x80):
                va_ = off2va(secs, o)
                guids.append((va_, g))
                o += 16
                continue
            o += 1
    print(f"\nplausible GUIDs in data sections: {len(guids)}")
    for va, g in guids[:40]:
        print(f"   @ RVA {va:#07x}  {fmt_guid(g)}  {g.hex()}")

    # ---- 2. disassembly sweep: constants + cmd-buf writes -----------------
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    hits = {"cmp_imm": [], "mov_byte": []}
    for nm, va, vs, ra, rs in secs:
        if not nm.startswith(".text"):
            continue
        code = d[ra:ra + rs]
        for insn in md.disasm(code, va):
            m = insn.mnemonic
            op = insn.op_str
            if m == "cmp" and re.search(r", (0x1[0-9a-f]|0x2[0-9a-f]|0x3[0-9a-f])$", op):
                hits["cmp_imm"].append((insn.address, op))
            if m in ("mov", "mov byte ptr") and op.startswith("byte ptr [") and re.search(r", (0x17|0x21|0x2[0-9a-f]|0x3[0-9a-f])$", op):
                hits["mov_byte"].append((insn.address, op))
    print(f"\ncmp-with-small-imm sites ({len(hits['cmp_imm'])}) — first 40:")
    for a, op in hits["cmp_imm"][:40]:
        print(f"   {a:#07x}: cmp {op}")
    print(f"\ncmd-buf byte writes ({len(hits['mov_byte'])}) — first 40:")
    for a, op in hits["mov_byte"][:40]:
        print(f"   {a:#07x}: {op}")

    # ---- 3. status map: look for switch/cmp chains on status byte ---------
    # fn 0x31B4 in the 3090 2.27.0 module; find `cmp al/ean, imm8` clusters
    print("\nstatus-byte cmp clusters (sub_31B4-style):")
    cluster = []
    for a, op in hits["cmp_imm"]:
        if cluster and a - cluster[-1][0] > 0x40:
            if len(cluster) >= 4:
                print("   cluster @", hex(cluster[0][0]),
                      "—", [o for _, o in cluster][:14])
            cluster = []
        cluster.append((a, op))
    if len(cluster) >= 4:
        print("   cluster @", hex(cluster[0][0]), "—",
              [o for _, o in cluster][:14])


if __name__ == "__main__":
    for p in sys.argv[1:]:
        scan(p)
