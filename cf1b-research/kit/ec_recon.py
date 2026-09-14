#!/usr/bin/env python3
"""ec_recon.py — annotated static recon for the Dell 5X90 EC (PHCM plaintext Thumb).

Adds to ec_analysis.py:
  * literal-pool annotation: every `ldr rX,[pc,#imm]` gets its u32 value
    (and symbolic name when known),
  * BL call-graph walking from a root function,
  * string / table xref search,
  * RAM/MMIO naming from the REPORT section-12 memory map.

Usage:
  python3 ec_recon.py <ec-bin> --dis ADDR N       annotated disassembly
  python3 ec_recon.py <ec-bin> --call ADDR [DEPTH] BL call graph
  python3 ec_recon.py <ec-bin> --xref V           find literal users of value V
  python3 ec_recon.py <ec-bin> --str SUBSTR       find ASCII string + literal xrefs
"""
import struct
import sys
import re

sys.path.insert(0, '.')
from ec_analysis import parse_phcm, get_disassembler

FLASH = 0x0D0000          # PHCM body mapping for 5X90 EC 1.00.51

NAMES = {
    0x118F90: "win0 (sel 0x10) - mailbox window 32B",
    0x118F92: "win2 (sel 0x12) sub/flags",
    0x118F93: "win3 (sel 0x13) count",
    0x118F94: "win4 (sel 0x14) payload[0..7]",
    0x118FAC: "svc record (sel 0x2C)",
    0x118FE4: "TBH state struct / counter",
    0x118FE8: "TBH captured bytes",
    0x118FE9: "TBH state byte",
    0x118DA0: "capture counter",
    0x1196BA: "engine stored-8",
    0x1196C2: "engine state byte",
    0x1182D0: "svc22 flag pair",
    0x1183A8: "fwupd RAM staging",
    0x400F0100: "MMIO doorbell/status out",
    0x400F0104: "MMIO status",
    0x400F0110: "MMIO msg/sync type",
    0x400F0111: "MMIO seq tag",
    0x400F0112: "MMIO role",
    0x400F0113: "MMIO payload[0]",
    0x400F011A: "MMIO payload[7]",
    0x400F1000: "eSPI capture block",
    0x400F1004: "eSPI cap +0x104 status bit3",
    0x400F1008: "eSPI cap +0x108 captured byte",
    0x400F3400: "eSPI I/O window module",
    0xF1FDC: "service table",
    0xF245EC: "64-char alphabet",
    0xF1F98: "str read_service_tag()",
    0xF1FAC: "str write_service_tag()",
}

SYMS = {
    0xDFAC4: "svc_dispatch", 0xDFB68: "svc_task_step",
    0xDFF99: "tramp_list4", 0xDFF6D: "tramp_pairs", 0xDFFC9: "tramp_alt",
    0xDEBBC: "svc22_sub_gate", 0xEFEBC: "engine_910", 0xEFEA0: "engine_clear_regs",
    0xEFE94: "engine_reset_state", 0xDFDF8: "post_event_1a", 0xDE08C: "post_event2",
    0xDECC0: "status_set", 0xDEC9C: "status_or", 0xDBBF4: "err_post",
    0xE1000: "memset", 0xE102C: "memcpy", 0xDBA54: "sem_inc", 0xDBA94: "sem_wait",
    0xE0C38: "cap_handler", 0xE0544: "tbh_dispatch", 0xE0AD0: "tbh_subcmd",
    0xE0FE1: "svc18_sub", 0xE0D1C: "svc18_mid", 0xE022E: "svc22_c3_branch",
    0xE01F0: "svc22_c3_tail", 0xE0520: "mod_reset_helper",
    0xD19F8: "io_trap_init", 0xE794: "fwupd_ED", 0xE644: "fwupd_EE",
    0xDE794: "c3_ED", 0xDE644: "c3_EE",
}


def name(v):
    if v in SYMS:
        return SYMS[v]
    if v in NAMES:
        return NAMES[v]
    return None


class Img:
    def __init__(self, path):
        data = open(path, 'rb').read()
        p = parse_phcm(data)
        self.body = p['body']
        self.base = FLASH
        self.md = get_disassembler()

    def off(self, addr):
        return addr - self.base

    def rd(self, addr, n):
        o = self.off(addr)
        return self.body[o:o + n]

    def u32(self, addr):
        return struct.unpack('<I', self.rd(addr, 4))[0]

    def u16(self, addr):
        return struct.unpack('<H', self.rd(addr, 2))[0]

    def dis(self, addr, n):
        """Annotated disassembly: decodes ldr-literal values, marks pools."""
        out = []
        pool_ann = {}
        code = self.rd(addr, n)
        for ins in self.md.disasm(code, addr):
            line = f"  0x{ins.address:08x}: {ins.mnemonic:<10} {ins.op_str}"
            m = re.match(r'ldr(?:\.w)?\s+r\d+,\s*\[pc,\s*#(0x[0-9a-f]+|\d+)\]', ins.mnemonic + ' ' + ins.op_str)
            if m:
                imm = int(m.group(1), 0)
                lit = (ins.address & ~3) + 4 + imm
                if 0 <= self.off(lit) <= len(self.body) - 4:
                    v = self.u32(lit)
                    nm = name(v)
                    extra = f"   ; ={v:#010x}" + (f" {nm}" if nm else "")
                    # is it code? try to resolve as function symbol
                    line += extra
                    pool_ann.setdefault(lit, set()).add(ins.address)
            out.append(line)
        return "\n".join(out)

    def callers_of(self, target):
        """Find BL (and b.w tail-calls) targeting addr.

        Raw halfword scan (immune to literal-pool desync).  The second
        halfword test must be (hw1 & 0xD000) == 0xD000 for BL -- a naive
        0xD000<=hw1<0xE000 range check silently misses J1=1 encodings whose
        second halfword is 0xF000+ (e.g. the BL at 0xE0C84 -> 0xE0544).
        """
        res = []
        for site, tgt, kind in self.branch_sites():
            if tgt == target:
                res.append((site, kind))
        return res

    def _hw(self):
        import struct as _s
        n = len(self.body) // 2
        return _s.unpack('<%dH' % n, self.body[:n * 2])

    def branch_sites(self):
        """Raw Thumb-2 immediate-branch decoder: (site, target, kind).

        kinds: 'bl', 'b.w', 'blx'.  hw0 0xF000-0xF7FF prefixes; hw1 pattern
        bits select the flavor: BL hw1&0xD000==0xD000, B.W ==0x9000,
        BLX ==0xC000.  Cached after first call.
        """
        if getattr(self, "_branch_cache", None) is not None:
            return self._branch_cache
        hw = self._hw()
        out = []
        for i in range(len(hw) - 1):
            a = hw[i]
            if not (0xF000 <= a < 0xF800):
                continue
            b = hw[i + 1]
            pat = b & 0xD000
            if pat == 0xD000:
                kind = 'bl'
            elif pat == 0x9000:
                kind = 'b.w'
            elif pat == 0xC000:
                kind = 'blx'
            else:
                continue
            S = (a >> 10) & 1
            imm10 = a & 0x3FF
            J1 = (b >> 13) & 1
            J2 = (b >> 11) & 1
            imm11 = b & 0x7FF
            I1 = 0 if (J1 ^ S) else 1
            I2 = 0 if (J2 ^ S) else 1
            off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S:
                off -= 1 << 25
            out.append((self.base + i * 2, self.base + i * 2 + 4 + off, kind))
        self._branch_cache = out
        return out

    def ldr_users(self, value):
        """Find all ldr-literal loads of a u32 value.

        Raw literal-anchored scan (linear capstone sweeps desync after the
        first data pool): locate the u32 in the image, then find T1/T2
        ldr-pc instructions whose computed literal address hits it.
        """
        import struct as _s
        res = []
        needle = _s.pack('<I', value)
        lits = set()
        off = self.body.find(needle)
        while off != -1:
            lits.add(off)
            off = self.body.find(needle, off + 1)
        if not lits:
            return res
        hw = self._hw()
        for i in range(len(hw)):
            a = hw[i]
            if (a >> 11) == 0b01001:          # ldr rt, [pc, #imm8*4] (T1)
                imm = (a & 0xFF) * 4
                pc = (self.base + i * 2 + 4) & ~3
                if (pc - self.base + imm) in lits:
                    res.append(self.base + i * 2)
            elif (a >> 11) == 0b11101:        # ldr.w rt, [pc, #imm12] (T2)
                try:
                    code = self.body[i * 2:i * 2 + 4]
                    for ins in self.md.disasm(code, self.base + i * 2):
                        m = re.match(r'ldr(\.w)?\s+r\d+,\s*\[pc,\s*#(-?0x[0-9a-f]+|-?\d+)\]',
                                     ins.mnemonic + ' ' + ins.op_str)
                        if m:
                            imm = int(m.group(2), 0)
                            pc = (ins.address + 4) & ~3
                            if (pc - self.base + imm) in lits:
                                res.append(ins.address)
                except Exception:
                    pass
        return res

    def strings(self, minlen=5):
        return [(m.start() + self.base, m.group().decode())
                for m in re.finditer(rb'[ -~]{%d,}' % minlen, self.body)]

    def find_string(self, sub):
        return [(a, s) for a, s in self.strings() if sub in s]


def call_graph(img, root, depth=2, _seen=None, _d=0):
    if _seen is None:
        _seen = set()
    if root in _seen or _d > depth:
        return []
    _seen.add(root)
    out = []
    code = img.rd(root, 0x400)
    for ins in img.md.disasm(code, root):
        if ins.mnemonic in ('bl', 'b.w'):
            try:
                t = int(ins.op_str.replace('#', ''), 0)
            except ValueError:
                continue
            if img.base <= t < img.base + len(img.body):
                nm = name(t) or ''
                out.append((ins.address, t, nm))
                out += call_graph(img, t, depth, _seen, _d + 1)
    return out


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(__doc__)
        return
    img = Img(args[0])
    mode = args[1]
    if mode == '--dis':
        addr = int(args[2], 0)
        n = int(args[3], 0) if len(args) > 3 else 0x80
        print(img.dis(addr, n))
    elif mode == '--call':
        addr = int(args[2], 0)
        depth = int(args[3]) if len(args) > 3 else 2
        print(f"call graph from {name(addr) or hex(addr)}:")
        for src, dst, nm in call_graph(img, addr, depth):
            print(f"  {src:#x} -> {dst:#x} {nm}")
    elif mode == '--xref':
        v = int(args[2], 0)
        us = img.ldr_users(v)
        print(f"literal users of {v:#x}: {[hex(u) for u in us]}")
        for u in us:
            print(img.dis(u - 0x20, 0x60))
    elif mode == '--callers':
        v = int(args[2], 0)
        print(f"BL/b.w callers of {v:#x} ({name(v) or ''}):")
        for a, mn in img.callers_of(v):
            print(f"  {a:#x}: {mn}")
    elif mode == '--str':
        sub = args[2]
        hits = img.find_string(sub)
        for a, s in hits:
            print(f"0x{a:#x}: {s!r}")
            for u in img.ldr_users(a):
                print(f"   xref ldr @ {u:#x}")
                print(img.dis(u - 0x10, 0x40))
    elif mode == '--sym':
        for k in sorted(NAMES):
            print(f"{k:#010x}  {NAMES[k]}")
        for k in sorted(SYMS):
            print(f"{k:#010x}  {SYMS[k]} (code)")
    else:
        print(__doc__)


if __name__ == '__main__':
    main()
