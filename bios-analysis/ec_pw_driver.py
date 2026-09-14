#!/usr/bin/env python3
"""
ec_pw_driver.py -- full-session emulation driver for the 5X90 EC password engine.

Drives the reversed engine (see FINDINGS_5X90_EC.md) at the protocol level:
  * 0xDF24C(cmd, byte)  -- the 0xA4..0xAE password-protocol dispatcher (tags 0xA0-0xAF)
  * 0xEBCD4             -- cmd-0x21 sub=2: receive 32-byte X into 0x1193E2
  * 0xEBC64             -- cmd-0x21 sub=1: verify
  * 0xEBA7C             -- challenge/suffix response builder (tag from NVRAM id 0xB or MMIO)
  * 0xEC05C / 0xEC0C8   -- verify cascades

Virtual environment:
  * synthetic EC NVRAM pages at flash-cache 0x716000/0x717000 (record format
    {len, payload..., id, 0xAA}, page magic {0xFF,0x55} at +0xFFE/+0xFFF)
  * flash reads (0xD1CFC/0xD1DD4) served directly from mapped memory
  * virtual host on the packet channel: [0x400F0112]=ready, [0x400F0113]=count,
    [0x400F0114..0x400F011B]=payload  (matches provider impl_write packets)
  * SMBus responses (0xDED28 -> [0x400F0400+0x100/0x108]) logged
"""
import struct
import sys

sys.path.insert(0, ".")
from ec_emulate import Emu, load, sym, SENTINEL, STACK_TOP
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_CODE, UcError
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP,
)
from unicorn import UcError

BODY = "ec_payloads/Latitude_5X90_1.41.0_ec_2_172864.bin"

NVRAM_CACHE = 0x6D0000          # [0x1183A8] staging base (flash cache window)
PAGE_A = NVRAM_CACHE + 0x46000  # 0x716000
PAGE_B = NVRAM_CACHE + 0x47000  # 0x717000

# ---------------------------------------------------------------- records ----
def make_record(rid: int, payload: bytes) -> bytes:
    ln = len(payload) + 3
    r = bytes([ln]) + payload + bytes([rid, 0xAA])
    stride = (ln + 3) & ~3
    r += b"\xFF" * (stride - len(r))
    return r

def make_page(records) -> bytes:
    page = bytearray(b"\xFF" * 0x1000)
    off = 0
    for rid, payload in records:
        r = make_record(rid, payload)
        page[off:off + len(r)] = r
        off += len(r)
    # page-valid magic: [0xFFE] = 0xFF, [0xFFF] = 0x55
    page[0xFFE] = 0xFF
    page[0xFFF] = 0x55
    return bytes(page)

# ------------------------------------------------------------------ driver ---
class EmuPw(Emu):
    # functions to stub out (return 0 immediately): 1ms delays etc.
    STUBS = {0xEB54C: None,          # delay(1000)
             0xDBA1C: 1,             # tick/timeout fn -> "expired" (breaks wait loops)
             0xDBA54: None,          # delay loop
             0xDDBD0: 0,             # page mount: keep [0x118E3C] as pre-set
             0xDDA60: 0,             # flash byte write -> stubbed (records logged in hk_stub)
             0xE00AA: 0}             # printf/log -> silent
    # flash read entry points: (addr=r0, len=r1, buf=r2)
    FLASH_READS = (0xD1CFC, 0xD1DD4)

    def __init__(self, body, records=None, trace=False):
        super().__init__(body, trace=trace)
        uc = self.uc
        # NVRAM flash-cache pages
        uc.mem_map(NVRAM_CACHE, 0x60000)
        recs = records if records is not None else DEFAULT_RECORDS
        page = make_page(recs)
        uc.mem_write(PAGE_A, page)
        uc.mem_write(PAGE_B, page)
        # staging pointer + mounted page
        self.wr(0x1183A8, NVRAM_CACHE)
        self.wr(0x118E3C, 0x46000)
        # protocol log
        self.smbus = []       # (pc, value) writes via 0xDED28
        self.recwrites = []   # NVRAM record writes via 0xDDFCE
        self.hostlog = []     # virtual-host packet deliveries
        self.queue = []       # bytes for the byte channel ([0x400F0112/0113])
        self.packets = []     # list of (count, payload8) for the packet channel
        self.cur = None       # current packet being consumed
        uc.hook_add(UC_HOOK_CODE, self.hk_stub, begin=0xD0000, end=0x100000)

    # -- code hook: stub delays, serve flash reads -------------------------
    def hk_stub(self, uc, addr, size, data):
        a = addr & ~1
        if a in self.STUBS:
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if a in self.FLASH_READS:
            r0 = uc.reg_read(UC_ARM_REG_R0)
            r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            try:
                buf = uc.mem_read(r0, r1)
                uc.mem_write(r2, bytes(buf))
            except UcError:
                pass
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if a == 0xDDFCE:      # NVRAM record write: (r0=id, r1=len); data = encBlock
            rid = uc.reg_read(UC_ARM_REG_R0)
            ln = uc.reg_read(UC_ARM_REG_R1)
            data = bytes(uc.mem_read(0x118F44, min(ln, 0x40)))
            self.recwrites.append((rid, ln, data))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if a == 0xDED28:      # SMBus send(r0)
            self.smbus.append((a, uc.reg_read(UC_ARM_REG_R0)))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if a == 0xDEAA4:      # doorbell poll: virtual doorbell 0x17 when packets queued
            if self.packets:
                self.wr(0x400F0110, bytes([0x17]))
                uc.reg_write(UC_ARM_REG_R0, 0)
            else:
                uc.reg_write(UC_ARM_REG_R0, 1)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return
        if a == 0xDEB04:      # packet poll: serve next packet into the regfile
            if self.packets:
                cnt, payload = self.packets.pop(0)
                self.cur = (cnt, payload)
                self.wr(0x400F0112, bytes([1]))            # ready
                self.wr(0x400F0113, bytes([cnt]))          # count (1 byte!)
                self.wr(0x400F0114, payload.ljust(8, b"\x00")[:8])
                self.hostlog.append(("packet", cnt, payload))
                uc.reg_write(UC_ARM_REG_R0, cnt)
            else:
                uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return

    # -- virtual host: the packet channel -----------------------------------
    def hk_read(self, uc, access, address, size, value, user):
        if address == 0x400F0100:      # doorbell/status
            if self.cur is None and self.packets:
                cnt, payload = self.packets[0]
                return 0x17            # doorbell 0x17 = data packet available
            return self._memread(address, 1)
        if address == 0x400F0112:      # ready/role
            if self.cur is None and self.packets:
                cnt, payload = self.packets.pop(0)
                self.cur = [cnt, bytearray(payload)]
                self.hostlog.append(("packet", cnt, bytes(payload)))
            base = super().hk_read and 0
            mem = self._memread(address, 1)
            if self.cur is not None:
                return (mem | 0x01) & 0xFF
            return mem
        if address == 0x400F0113:      # count
            if self.cur is not None:
                return self.cur[0] & 0xFF
            return self._memread(address, 1)
        if 0x400F0114 <= address <= 0x400F011B:  # payload bytes
            if self.cur is not None:
                idx = address - 0x400F0114
                return self.cur[1][idx]
            return self._memread(address, 1)
        return super().hk_read(uc, access, address, size, value, user)

    def _memread(self, address, size):
        try:
            return int.from_bytes(self.uc.mem_read(address, size), "little")
        except UcError:
            return 0

    def hk_write(self, uc, access, address, size, value, user):
        # EC consumed the packet when it clears [0x400F0112] = 0
        if address == 0x400F0112 and (value & 0xFF) == 0 and self.cur is not None:
            self.cur = None
        if address in (0x400F0100, 0x400F0110, 0x400F0111):
            self.hostlog.append((f"w{address-0x400F0000:03x}", value & 0xFF))
        return super().hk_write(uc, access, address, size, value, user)

    # -- helpers -------------------------------------------------------------
    def send_packet(self, count, payload):
        self.packets.append((count, payload.ljust(8, b"\x00")[:8]))

    def rd(self, a, n):
        return bytes(self.uc.mem_read(a, n))

    def callx(self, addr, r0=0, r1=0, r2=0, r3=0, count=8_000_000):
        return self.call(addr, r0=r0, r1=r1, r2=r2, r3=r3, count=count)

# default synthetic NVRAM: tag+family record 0xB, password records, response 3
DEFAULT_RECORDS = [
    (0x0B, b"H2FS5S38FC8"),                 # tag(7) + family(4)  (11 bytes)
    (0x03, b"R" * 32),                      # the 32-byte response record
    (0x04, b"ADMINPW444444444"),            # password class 4
    (0x05, b"SYSPW5555555555"),             # password class 5
    (0x15, b"MASTERPW1555555"),             # password class 0x15
    (0x21, b"N" * 32),                      # 33-byte record used by 0xEB634
    (0x2A, b"\x01"),                        # flag written on tag write
    (0x31, b"+e"),                          # seen printable in real dump
]

def new_driver(records=None, trace=False):
    return EmuPw(load(BODY), records=records, trace=trace)

# ------------------------------------------------------------------ tests ----
ASCII72 = (b"012345679abcdefghijklmnopqrstuvwxyz0123456789"
           b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0")[:72]

def render(x):
    """The EC's 0xEBFA4 rendering: ascii72[b % 72]."""
    return bytes(ASCII72[b % 72] for b in x)

def run(e, addr, r0=0):
    """Call a function directly (no r1-r3 mangling, fresh frame)."""
    from ec_emulate import SENTINEL, STACK_TOP
    from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR
    uc = e.uc
    e.wr(0x400F3400 + 0x33C, 0x09100001)
    uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
    uc.reg_write(UC_ARM_REG_R0, r0)
    uc.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
    e.stop = False
    try:
        uc.emu_start(addr | 1, SENTINEL, timeout=0, count=8_000_000)
        return "ok"
    except Exception as ex:
        return f"EXC {ex}"

def ret(e):
    from unicorn.arm_const import UC_ARM_REG_R0
    return e.uc.reg_read(UC_ARM_REG_R0)

def check(name, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: got {got!r} want {want!r}")
    return ok

def selftest():
    import dell_keygen as dk
    all_ok = True

    print("== T1: challenge/suffix response (0xEBA7C) ==")
    e = new_driver(); e.wr(0x400F0112, 0)
    run(e, 0xEBA7C)
    all_ok &= check("role0 NVRAM tag H2FS5S3+8FC8 -> suffix",
                    e.rd(0x400F0113, 8), b"10l6leru")
    all_ok &= check("python calculateSuffix_fw agrees",
                    dk.calculateSuffix_fw("H2FS5", ASCII72.decode(), 72),
                    "10l6leru")
    e = new_driver(); e.wr(0x400F0112, 1); e.wr(0x400F0113, b"8FC8CF1B0000")
    run(e, 0xEBA7C)
    all_ok &= check("role1 host tag 8FC8.. -> suffix", e.rd(0x400F0113, 8),
                    b"2b4rrrbb")

    print("== T2: sub=2 X receive (0xEBCD4), 4x8B packets + terminator ==")
    e = new_driver()
    X = bytes(range(0x41, 0x61))
    for i in range(0, 32, 8):
        e.send_packet(8, X[i:i+8])
    e.send_packet(0, b"")
    run(e, 0xEBCD4)
    all_ok &= check("X landed in 0x1193E2", e.rd(0x1193E2, 0x20), X)
    all_ok &= check("seq = 0xFA", e.rd(0x400F0111, 1), b"\xfa")

    print("== T3: verify cascade (0xEC05C) flag gates ==")
    X = bytes(range(0x10, 0x30)); P = render(X[:16])
    cases = [
        ("record 4 match",          b"ADMINPW444444444", 0x00, 1),
        ("record 5 match +bit1",    b"SYSPW5555555555",  0x02, 1),
        ("record 5 match no bit1",  b"SYSPW5555555555",  0x00, 0),
        ("render(X) match +bit3",   P,                   0x08, 1),
        ("render(X) match no bit3", P,                   0x00, 0),
        ("record 15 match +bit5",   b"MASTERPW1555555",  0x20, 1),
        ("record 15 match no bit5", b"MASTERPW1555555",  0x00, 0),
        ("no match at all",         b"WRONGWRONGWRONG",  0x2A, 0),
    ]
    for name, pw, flags, want in cases:
        e = new_driver()
        e.wr(0x1193E2, X)
        e.wr(0x119450, pw + b"\x00" * (32 - len(pw)))
        e.wr(0x1193E1, bytes([0])); e.wr(0x119403, bytes([flags]))
        run(e, 0xEC05C)
        all_ok &= check(name, ret(e), want)

    print("== T4: master enroll sub=8 (0xEBCF0) -> record 0x15 ==")
    e = new_driver()
    e.wr(0x119403, bytes([0])); e.wr(0x1193E1, bytes([0]))
    for i in range(0, 32, 8):
        e.send_packet(8, b"shzNyjGRzRN2LLzL"[i:i+8].ljust(8, b"\x00"))
    e.send_packet(0, b"")
    e.recwrites.clear()
    run(e, 0xEBCF0)
    all_ok &= check("record 0x15 written",
                    [(r, d.rstrip(b"\x00")) for r, _, d in e.recwrites],
                    [(0x15, b"shzNyjGRzRN2LLzL")])
    all_ok &= check("bit5 set in 0x119403", e.rd(0x119403, 1), b"\x20")

    print("== T5: admin enroll sub=0 (0xEBC1C) -> record 4 ==")
    e = new_driver()
    e.wr(0x119403, bytes([0])); e.wr(0x1193E1, bytes([0]))
    for i in range(0, 32, 8):
        e.send_packet(8, b"AdminTestPassword"[i:i+8])
    e.send_packet(0, b"")
    e.recwrites.clear()
    run(e, 0xEBC1C)
    all_ok &= check("record 4 written",
                    [(r, d.rstrip(b"\x00")) for r, _, d in e.recwrites],
                    [(4, b"AdminTestPassword")])

    print("== T6: challenge record 3 round-trip (0xEB634) ==")
    e = new_driver()
    ch = bytes([0x20]) + bytes(range(0xA0, 0xC0))
    e.wr(0x11942C, ch); e.wr(0x119408, bytes([0]))
    e.recwrites.clear()
    run(e, 0xEB634)
    all_ok &= check("record 3 (33B) written",
                    [(r, d) for r, _, d in e.recwrites],
                    [(3, ch)])

    print("== T7: 0xA4-0xAE console protocol (0xDF24C) ==")
    e = new_driver()
    for ch_ in b"PASSWORD123":
        e.callx(0xDF24C, r0=0xA5, r1=ch_)
    e.callx(0xDF24C, r0=0xA5, r1=0)
    all_ok &= check("string collected (1-byte preamble swallowed)",
                    e.rd(0x119409, 10), b"ASSWORD123")
    e.smbus.clear(); e.callx(0xDF24C, r0=0xA4, r1=0)
    all_ok &= check("0xA4 -> 0xFA", [v for _, v in e.smbus], [0xFA])
    e.smbus.clear(); e.callx(0xDF24C, r0=0xAA, r1=0)
    all_ok &= check("0xAA -> 0x55", [v for _, v in e.smbus], [0x55])

    print("ALL PASS" if all_ok else "SOME FAILURES")
    return 0 if all_ok else 1

if __name__ == "__main__":
    raise SystemExit(selftest())
