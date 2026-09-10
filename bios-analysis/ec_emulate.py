#!/usr/bin/env python3
"""ec_emulate.py — ARM Cortex-M (Thumb) emulation harness for Dell EC firmware.

Runs the EC's mailbox/challenge code from the PHCM dump inside Unicorn —
no hardware needed. Developed for the Latitude 5X90 EC 1.00.51 (plaintext,
see REPORT.md section 12), whose flash layout is:

    0x0D0000..0x0FA300   PHCM body (code 0xDxxxx, data/tables 0xFxxxx)
    0x100000..0x11A000   SRAM (mailbox window 0x118F90, service record
                          0x118FAC, challenge state 0x1196C2, stored-8
                          0x1196BA, flags 0x1182D0..)
    0x40000000..         MMIO (eSPI I/O window 0x400F0100/0x400F3400,
                          SMBus 0x400F0400, UART 0x40006400, ...)

Host-visible register file (challenge engine 0xEFEBC):
    [0x400F0110] message/sync type (0x78 data, 0xED/0xEE/0xC3 special, 0xC ...)
    [0x400F0111] sequence tag
    [0x400F0112] role (1=store 8B, 2=compare 8B, 3=status)
    [0x400F0113..0x400F011A] 8-byte payload
    [0x400F0100] status

Usage:
    python3 ec_emulate.py <ec.bin> --validate          # engine store/compare test
    python3 ec_emulate.py <ec.bin> --svc 22            # dispatch service 0x22
    python3 ec_emulate.py <ec.bin> --svc 22 --msg 0xED # preset message type
    python3 ec_emulate.py <ec.bin> --engine            # drive 0xEFEBC with a
                                                       # full host packet seq
Options: --trace (log all calls), --maxmmio N, --out file
"""
import argparse
import struct
import sys

try:
    from unicorn import *
    from unicorn.arm_const import *
except ImportError:
    sys.exit("pip install unicorn")

FLASH_BASE = 0x0D0000
FLASH_SIZE = 0x030000
RAM_BASE = 0x100000
RAM_SIZE = 0x020000
STACK_MAP = 0x2FFF0000
STACK_SIZE = 0x00020000
STACK_TOP = 0x3000FF00
MMIO_BASE = 0x40000000
MMIO_SIZE = 0x00100000
SENTINEL = 0x0DEFACE0

SYMS = {
    0x0DFAC4: "svc_dispatch",       0x0DFB68: "svc_task_step",
    0x0DFF99: "tramp_list4",        0x0DFF6D: "tramp_pairs",
    0x0DFFC9: "tramp_alt",          0x0DEBBC: "svc22_sub_gate",
    0x0EFEBC: "engine_910",         0x0EFEA0: "engine_clear_regs",
    0x0EFE94: "engine_reset_state", 0x0DFDF8: "post_event_1a",
    0x0DE08C: "post_event2",        0x0DECC0: "status_set",
    0x0DEC9C: "status_or",          0x0DBBF4: "err_post",
    0x0E1000: "memset",             0x0E102C: "memcpy",
    0x0DBA54: "sem_inc",            0x0DBA94: "sem_wait",
    0x0DBAEC: "chk1",               0x0DBB9C: "post2",
    0x0DBF4:  "sem2",               0x0DD44A: "mutex",
    0x0E00AA: "dbg_log",            0x0D19F8: "io_window_init",
    0x0DEEED: "queue_proc",         0x0DED78: "led_step",
    0x0EB2E4: "uart_xchg",          0x0EB3C6: "uart_cmd",
    0x0EECF0: "batt_temp",          0x0EF6C8: "adc_tick",
}

WIN_REGS = 0x400F0100
RAM_WATCH = [(0x118F90, 0x118FD0, "win+svc"),
             (0x1196B0, 0x1196D0, "challenge"),
             (0x1182C0, 0x1182F0, "flags28xx")]


def sym(a):
    return SYMS.get(a & ~1, f"{a:#x}")


class Emu:
    def __init__(self, body, trace=False):
        self.body = body
        self.trace = trace
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
        uc = self.uc
        uc.mem_map(FLASH_BASE, FLASH_SIZE)
        uc.mem_write(FLASH_BASE, body[:FLASH_SIZE])
        uc.mem_map(RAM_BASE, RAM_SIZE)
        uc.mem_map(STACK_MAP, STACK_SIZE)
        uc.mem_map(MMIO_BASE, MMIO_SIZE)
        self.calls = []          # (from, to)
        self.mmio = []           # (pc, 'r'/'w', addr, size, val)
        self.ramw = []           # writes to watched RAM
        self.stop = False
        uc.hook_add(UC_HOOK_CODE, self.hk_code)
        uc.hook_add(UC_HOOK_MEM_WRITE, self.hk_write)
        uc.hook_add(UC_HOOK_MEM_READ, self.hk_read)

    def hk_code(self, uc, addr, size, data):
        if addr == SENTINEL or addr == SENTINEL | 1:
            self.stop = True
            uc.emu_stop()
            return
        if not self.trace:
            return
        try:
            b = uc.mem_read(addr, 4)
        except Exception:
            return
        h = struct.unpack("<H", b[:2])[0]
        # BL (T1) / BLX imm (T2)
        if (h & 0xF800) == 0xF000:
            h2 = struct.unpack("<H", b[2:4])[0]
            if (h2 & 0xD000) == 0xD000 or (h2 & 0xD000) == 0xC000:
                off = ((h & 0x7FF) << 11) | (h2 & 0x7FF)
                if off & 0x200000:
                    off -= 0x400000
                tgt = addr + 4 + 2 * off
                self.calls.append((addr, tgt & ~1))
        # BLX Rm (0x4780 | Rm<<3): resolve register value at runtime
        elif (h & 0xFF87) == 0x4780:
            rm = (h >> 3) & 7
            try:
                val = uc.reg_read(UC_ARM_REG_R0 + rm)
            except Exception:
                val = 0
            if val:
                self.calls.append((addr, val & ~1))
            else:
                self.calls.append((addr, -1))

    def _watched(self, addr):
        for lo, hi, _ in RAM_WATCH:
            if lo <= addr < hi:
                return True
        return False

    def hk_write(self, uc, access, addr, size, value, data):
        if addr >= MMIO_BASE:
            self.mmio.append((uc.reg_read(UC_ARM_REG_PC), "w", addr, size, value))
        elif self._watched(addr):
            self.ramw.append((uc.reg_read(UC_ARM_REG_PC), "w", addr, size, value))

    def hk_read(self, uc, access, addr, size, value, data):
        if addr >= MMIO_BASE:
            self.mmio.append((uc.reg_read(UC_ARM_REG_PC), "r", addr, size, 0))

    # ---- helpers -------------------------------------------------------
    def rd(self, a, n=4):
        return bytes(self.uc.mem_read(a, n))

    def wr(self, a, b):
        if isinstance(b, int):
            b = struct.pack("<I", b)
        self.uc.mem_write(a, b)

    def call(self, addr, r0=0, r1=0, r2=0, r3=0, count=8_000_000, arm_port=True):
        uc = self.uc
        if arm_port:
            # eSPI I/O window: "trapped port" register must read 0x0910<<16
            self.wr(0x400F3400 + 0x33C, 0x09100001)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        uc.reg_write(UC_ARM_REG_R0, r0)
        uc.reg_write(UC_ARM_REG_R1, r1)
        uc.reg_write(UC_ARM_REG_R2, r2)
        uc.reg_write(UC_ARM_REG_R3, r3)
        uc.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
        self.stop = False
        try:
            uc.emu_start(addr | 1, SENTINEL, timeout=0, count=count)
        except UcError as e:
            pc = uc.reg_read(UC_ARM_REG_PC)
            return f"EXC {e} @ {sym(pc)}"
        pc = uc.reg_read(UC_ARM_REG_PC)
        if self.stop or (pc & ~1) == SENTINEL:
            return "ok"
        return f"stopped @ {sym(pc)}"


def load(path):
    data = open(path, "rb").read()
    if data[:4] != b"PHCM":
        sys.exit("not a PHCM container")
    hs = struct.unpack_from("<I", data, 0x14)[0]
    return data[hs:len(data) - hs]


def report(e: Emu, out=None):
    lines = []
    lines.append(f"executed calls: {len(e.calls)}")
    seq, seen = [], set()
    for frm, tgt in e.calls:
        if tgt == -1:
            seq.append(f"{sym(frm)} -> blx reg")
        else:
            s = sym(tgt)
            if s not in seen:
                seq.append(f"{sym(frm)} -> {s}")
                seen.add(s)
    lines.append("first-time call targets in order:")
    lines.extend("  " + s for s in seq[:80])
    lines.append(f"MMIO accesses: {len(e.mmio)}")
    agg = {}
    for pc, k, a, sz, v in e.mmio:
        agg[(k, a)] = agg.get((k, a), 0) + 1
    for (k, a), n in sorted(agg.items(), key=lambda kv: -kv[1])[:40]:
        lines.append(f"  {k} {a:#010x} x{n}")
    lines.append("watched-RAM writes:")
    for pc, k, a, sz, v in e.ramw[:60]:
        lines.append(f"  {sym(pc)} w {a:#x} <- {v & ((1 << (8*sz)) - 1):#x}")
    txt = "\n".join(lines)
    print(txt)
    if out:
        open(out, "w").write(txt + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bin")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--engine", action="store_true")
    ap.add_argument("--svc", type=lambda s: int(s, 0))
    ap.add_argument("--msg", type=lambda s: int(s, 0))
    ap.add_argument("--req", type=lambda s: int(s, 0), help="requester word at 0x118FAC")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()

    body = load(args.bin)
    e = Emu(body, trace=True)          # always trace calls; --trace adds nothing extra yet
    e.stop = False

    if args.validate:
        # engine store/compare semantics
        e.wr(0x1196C2, b"\x00")                    # state = 0
        e.wr(0x400F0110, b"\x78\x01\x01" + b"AAAAAAAA")   # sync, tag, role=1(store)
        r = e.call(0xEFEBC)
        stored = e.rd(0x1196BA, 8)
        state = e.rd(0x1196C2, 1)[0]
        print(f"store: rc={r} stored={stored!r} state={state} (want b'AAAAAAAA', 1)")
        e.wr(0x400F0110, b"\x78\x02\x02" + b"AAAAAAAA")   # role=2 compare (match)
        r = e.call(0xEFEBC)
        print(f"compare-match: rc={r} state={e.rd(0x1196C2,1)[0]} (want 2)")
        e.wr(0x400F0110, b"\x78\x03\x02" + b"BBBBBBBB")   # role=2 compare (mismatch)
        r = e.call(0xEFEBC)
        print(f"compare-mismatch: rc={r} state={e.rd(0x1196C2,1)[0]} (want 2 w/ err)")
        return

    if args.engine:
        # full host packet sequence, as the probe tool would send it
        e.wr(0x1196C2, b"\x00")
        for i, pkt in enumerate([b"\x01" + b"XXXXXXXXYYYYYYYY"[:8],
                                 b"\x02" + b"XXXXXXXXYYYYYYYY"[8:]]):
            e.wr(0x400F0110, b"\x78" + bytes([i + 1]) + pkt)
            print(f"packet {i}: rc={e.call(0xEFEBC)} state={e.rd(0x1196C2,1)[0]}")
        print("stored16:", e.rd(0x1196BA, 8).hex(), e.rd(0x1196C2 - 8, 8).hex())
        return

    if args.svc is not None:
        if args.msg is not None:
            e.wr(0x400F0110, bytes([args.msg & 0xFF]))
        # service request word: {u16 svc, u8 requester, u8 valid}
        req = args.req if args.req is not None else ((args.svc) | (0x01 << 16) | (0x01 << 24))
        e.wr(0x118FAC, req)
        r = e.call(0xDFAC4, r0=args.svc, r1=0x55)
        print(f"svc {args.svc:#x}: rc={r}")
        print("window+svc record:", e.rd(0x118F90, 0x40).hex())
        print("challenge RAM:", e.rd(0x1196B0, 0x20).hex())
        report(e, args.out)
        return

    print(__doc__)


if __name__ == "__main__":
    main()
