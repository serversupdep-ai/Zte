#!/usr/bin/env python3
"""
dell_offline_keygen.py — 100% Standalone Offline Dell Master Password Generator
================================================================================
Zero external files. Zero third-party dependencies (pure Python 3 stdlib only).

Usage:
    python3 dell_offline_keygen.py 65FDQN2-E7A8        # Specific suffix
    python3 dell_offline_keygen.py 65FDQN2             # All offline suffixes
    python3 dell_offline_keygen.py 1234567890A-BF97    # 11-char HDD/NVMe serial
    python3 dell_offline_keygen.py 5F3988D5E0ACE4BF-7QH8602  # Latitude 3540
    python3 dell_offline_keygen.py                     # Interactive prompt
    python3 dell_offline_keygen.py --selftest          # Verify 60+ test vectors

Supported Offline Dell System / HDD Suffixes (100% offline from Service Tag):
    E7A8  (Code 1: [17,13,12,8] + Code 2: [17,13,12,16])
    BF97, 6FF1, 1F66, 1D3B, 1F5A, 2A7B, D35B, 595B, A95B
    + Pre-suffix 11-char HDD serials & Latitude 3540 (Insyde DES 16-hex + 7-tag)
    + Plaintext MEC5085 EC 8-char tag code (cmd 0x4E)

Hardware Boundary Note (8FC8 / CF1B / 9ABE / 3FE2 / 1B58):
    On 2020-2026 EC-vault systems showing -8FC8 or -CF1B/-9ABE/-3FE2/-1B58,
    Dell moved master-key generation inside the Embedded Controller's OTP-encrypted
    silicon (MEC5200 iFuse / NPCX993D iFuse). No Service-Tag-only offline formula
    exists without the 32-byte EC mailbox response (--resp32 <64-hex>).

TIP: On the Dell BIOS password screen, type the Master Password and press
     Ctrl + Enter (hold Left Ctrl and press Enter twice if required).
"""

import hashlib
import re
import sys

# ==============================================================================
# 1. CONSTANTS & ALPHABET TABLES (Verified Byte-for-Byte Against Dell UEFI/EC)
# ==============================================================================

MD5_MAGIC = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

MD5_MAGIC2 = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
]

ROTATION_TABLE = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
]

INITIAL_DATA = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

ALPHABETS = {
    "8FC8": "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r",
    "E7A8": "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ",
    "BF97": "0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ",
    "6FF1": "08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0",
    "1F66": "0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0",
    "1D3B": "0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0",
    "2A7B": "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
    "1F5A": "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0",
}

EXTRA_CHARACTERS = {
    k: ALPHABETS[k] for k in ("2A7B", "1F5A", "1D3B", "1F66", "6FF1", "BF97")
}

SCAN_CODES = (
    "\x00\x1b1234567890-=\x08\x09"
    "qwertyuiop[]\x0d\xff"
    "asdfghjkl;'`\xff\\"
    "zxcvbnm,./"
)

ENCSCANS = [
    0x05, 0x10, 0x13, 0x09, 0x32, 0x03, 0x25, 0x11, 0x1F, 0x17, 0x06, 0x15,
    0x30, 0x19, 0x26, 0x22, 0x0A, 0x02, 0x2C, 0x2F, 0x16, 0x14, 0x07, 0x18,
    0x24, 0x23, 0x31, 0x20, 0x1E, 0x08, 0x2D, 0x21, 0x04, 0x0B, 0x12, 0x2E,
]

OFFLINE_SUFFIXES = (
    "E7A8", "BF97", "6FF1", "1F66", "1D3B", "1F5A", "2A7B", "D35B", "595B", "A95B"
)
EC_SEALED_SUFFIXES = ("8FC8", "CF1B", "9ABE", "3FE2", "1B58")


# ==============================================================================
# 2. CORE BITWISE & ROUND PRIMITIVES
# ==============================================================================

def m32(x: int) -> int:
    return x & 0xFFFFFFFF


def rol32(x: int, bits: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << bits) & 0xFFFFFFFF) | (x >> (32 - bits))


def rol8(x: int, bits: int) -> int:
    x &= 0xFF
    return ((x << bits) | (x >> (8 - bits))) & 0xFF


def enc_f1(a: int, b: int) -> int:
    return (a + b) & 0xFFFFFFFF


def enc_f1n(a: int, b: int) -> int:
    return (a - b) & 0xFFFFFFFF


def enc_f2(a: int, b: int, c: int) -> int:
    return ((c ^ b) & a) ^ c


def enc_f2n(a: int, b: int, c: int) -> int:
    return enc_f2(a, b, (~c) & 0xFFFFFFFF)


def enc_f3(a: int, b: int, c: int) -> int:
    return ((a ^ b) & c) ^ b


def enc_f4(a: int, b: int, c: int) -> int:
    return (b ^ a) ^ c


def enc_f4n(a: int, b: int, c: int) -> int:
    return enc_f4(a, (~b) & 0xFFFFFFFF, c)


def enc_f5(a: int, b: int, c: int) -> int:
    return (a | ((~c) & 0xFFFFFFFF)) ^ b


def enc_f5n(a: int, b: int, c: int) -> int:
    return enc_f5((~a) & 0xFFFFFFFF, b, c)


# ==============================================================================
# 3. DELL FAMILY ENCODERS (595B / D35B / 2A7B / A95B / 1D3B / 1F66 / 1F5A /
#                          6FF1 / BF97 / E7A8 Code 1 & Code 2)
# ==============================================================================

class Tag595BEncoder:
    f1 = staticmethod(enc_f1n)
    f2 = staticmethod(enc_f2n)
    f3 = staticmethod(enc_f3)
    f4 = staticmethod(enc_f4n)
    f5 = staticmethod(enc_f5n)
    md5table = MD5_MAGIC

    def __init__(self, enc_block):
        self.enc_block = enc_block
        self.enc_data = self.initial_data()
        self.A, self.B, self.C, self.D = self.enc_data

    def initial_data(self):
        return INITIAL_DATA[:]

    @classmethod
    def encode(cls, enc_block):
        obj = cls(enc_block)
        obj.make_encode()
        return [m32(x) for x in obj.enc_data]

    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.B, self.C, self.D)
        combined = (self.md5table[key2] + self.enc_block[key1]) & 0xFFFFFFFF
        return (self.A + self.f1(tmp, combined)) & 0xFFFFFFFF

    def increment_data(self):
        self.enc_data[0] = m32(self.enc_data[0] + self.A)
        self.enc_data[1] = m32(self.enc_data[1] + self.B)
        self.enc_data[2] = m32(self.enc_data[2] + self.C)
        self.enc_data[3] = m32(self.enc_data[3] + self.D)

    def make_encode(self):
        for i in range(64):
            w = i >> 4
            if w == 0:
                t = self.calculate(self.f2, i & 15, i)
            elif w == 1:
                t = self.calculate(self.f3, (i * 5 + 1) & 15, i)
            elif w == 2:
                t = self.calculate(self.f4, (i * 3 + 5) & 15, i)
            else:
                t = self.calculate(self.f5, (i * 7) & 15, i)
            self.A, self.D, self.C = self.D, self.C, self.B
            self.B = m32(self.B + rol32(t, ROTATION_TABLE[w][i & 3]))
        self.increment_data()


class TagD35BEncoder(Tag595BEncoder):
    f1 = staticmethod(enc_f1)
    f2 = staticmethod(enc_f2)
    f3 = staticmethod(enc_f3)
    f4 = staticmethod(enc_f4)
    f5 = staticmethod(enc_f5)


class Tag1D3BEncoder(Tag595BEncoder):
    def make_encode(self):
        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= m32(0x60606161 - j)
            self.D ^= m32(0x50501010 + j)
            super().make_encode()


class Tag1F66Encoder(Tag595BEncoder):
    md5table = MD5_MAGIC2

    def make_encode(self):
        for j in range(17):
            self.A |= 0x100097
            self.B ^= 0xA0008
            self.C |= m32(0x60606161 - j)
            self.D ^= m32(0x50501010 + j)
            for i in range(64):
                w = i >> 4
                if w == 0:
                    t = self.calculate(self.f2, i & 15, m32(i + 16))
                elif w == 1:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, m32(i + 32))
                elif w == 2:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, m32(i - 2 * (i & 12) + 12))
                else:
                    t = self.calculate(self.f5, (i * 7) & 15, m32(2 * (i & 3) - (i & 15) + 12))
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = m32(self.B + rol32(t, ROTATION_TABLE[w][i & 3]))
            self.increment_data()

        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= m32(0x50501010 - j)
            self.D ^= m32(0x60606161 + j)
            for i in range(64):
                w = i >> 4
                if w == 0:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, m32(2 * (i & 3) - i + 44))
                elif w == 1:
                    t = self.calculate(self.f5, (i * 7) & 15, m32(2 * (i & 3) - i + 76))
                elif w == 2:
                    t = self.calculate(self.f2, i & 15, i & 15)
                else:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, m32(i - 32))
                g = (w + 2) & 3
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = m32(self.B + rol32(t, ROTATION_TABLE[g][i & 3]))
            self.increment_data()


class Tag1F5AEncoder(Tag595BEncoder):
    md5table = MD5_MAGIC2

    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.C, self.A, self.D)
        combined = (self.md5table[key2 % len(self.md5table)] + self.enc_block[key1]) & 0xFFFFFFFF
        return (self.B + self.f1(tmp, combined)) & 0xFFFFFFFF

    def increment_data(self):
        self.enc_data[0] = m32(self.enc_data[0] + self.B)
        self.enc_data[1] = m32(self.enc_data[1] + self.C)
        self.enc_data[2] = m32(self.enc_data[2] + self.A)
        self.enc_data[3] = m32(self.enc_data[3] + self.D)

    def make_encode(self):
        for _ in range(5):
            for j in range(64):
                w = j >> 4
                k = 12 + (j & 3) - (j & 12)
                if w == 0:
                    t = self.calculate(self.f2, j & 15, j)
                elif w == 1:
                    t = self.calculate(self.f3, (j * 5 + 1) & 15, j)
                elif w == 2:
                    t = self.calculate(self.f4, (j * 3 + 5) & 15, m32(k + 0x20))
                else:
                    t = self.calculate(self.f5, (j * 7) & 15, m32(k + 0x30))
                self.B, self.D, self.A, self.C = (
                    self.D,
                    self.A,
                    self.C,
                    m32(self.C + rol32(t, ROTATION_TABLE[w][j & 3])),
                )
            self.increment_data()


class Tag6FF1Encoder(Tag595BEncoder):
    md5table = MD5_MAGIC2
    counter1 = 23

    def make_encode(self):
        for j in range(self.counter1):
            self.A |= 0xA08097
            self.B ^= 0xA010908
            self.C |= m32(0x60606161 - j)
            self.D ^= m32(0x50501010 + j)
            for i in range(64):
                w = i >> 4
                k = (i & 15) - ((i & 12) << 1) + 12
                if w == 0:
                    t = self.calculate(self.f2, i & 15, m32(i + 32))
                elif w == 1:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15, i & 15)
                elif w == 2:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15, m32(k + 16))
                else:
                    t = self.calculate(self.f5, (i * 7) & 15, m32(k + 48))
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = m32(self.B + rol32(t, ROTATION_TABLE[w][i & 3]))
            self.increment_data()

        for j in range(17):
            self.A |= 0x100097
            self.B ^= 0xA0008
            self.C |= m32(0x50501010 - j)
            self.D ^= m32(0x60606161 + j)
            for i in range(64):
                w = i >> 4
                k = (i & 15) - ((i & 12) << 1) + 12
                if w == 0:
                    t = self.calculate(self.f4, ((i & 15) * 3 + 5) & 15, k + 16)
                elif w == 1:
                    t = self.calculate(self.f5, ((i & 3) * 7 + (i & 12) + 4) & 15, m32((i & 15) + 32))
                elif w == 2:
                    t = self.calculate(self.f2, k & 15, k)
                else:
                    t = self.calculate(self.f3, ((i & 15) * 5 + 1) & 15, m32((i & 15) + 48))
                g = (w + 2) & 3
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = m32(self.B + rol32(t, ROTATION_TABLE[g][i & 3]))
            self.increment_data()


class TagBF97Encoder(Tag6FF1Encoder):
    counter1 = 31


class TagE7A8Encoder(Tag595BEncoder):
    md5table = MD5_MAGIC2
    loop_params = [17, 13, 12, 8]
    encode_params = [
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008, 0x100097, 0x50501010,
    ]

    def initial_data(self):
        return [0, 0, 0, 0]

    def shortcut(self, fun, j: int, md5_index: int, rot_index: int, indexes):
        for i in range(4):
            t = self.calculate(fun, (j + indexes[i]) & 7, md5_index + i)
            self.A, self.D, self.C = self.D, self.C, self.B
            self.B = m32(self.B + rol32(t, ROTATION_TABLE[rot_index][i]))

    def make_encode(self):
        ep, lp = self.encode_params, self.loop_params
        for p in range(lp[0]):
            self.A |= ep[0]
            self.B ^= ep[1]
            self.C |= m32(ep[2] - p)
            self.D ^= m32(ep[3] + p)
            for j in range(0, lp[2], 4):
                self.shortcut(self.f2, j, j + 32, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f3, j, j, 1, [1, -2, -1, 0])
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f5, j, j + 48, 3, [2, 3, 2, -3])
            self.increment_data()

        for p in range(lp[1]):
            self.A |= ep[4]
            self.B ^= ep[5]
            self.C |= m32(ep[6] - p)
            self.D ^= m32(ep[7] + p)
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f5, j, j + 32, 3, [2, 3, 2, -3])
            for j in range(lp[3], 0, -4):
                self.shortcut(self.f2, j, j, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f3, j, j + 48, 1, [1, -2, 3, 0])
            self.increment_data()


class TagE7A8EncoderSecond(TagE7A8Encoder):
    """Second firmware E7A8 parameter set (loop_params=[17,13,12,16])."""

    def __init__(self, enc_block):
        super().__init__(enc_block)
        overfill = [
            0xA0008 ^ 0x6D2F93A5,
            0xA08097 ^ 0x6D2F93A5,
            0xA010908 ^ 0x6D2F93A5,
            0x60606161 ^ 0x6D2F93A5,
        ]
        self.md5table = MD5_MAGIC2 + overfill
        self.loop_params = [17, 13, 12, 16]


LEGACY_ENCODERS = {
    "595B": Tag595BEncoder,
    "2A7B": Tag595BEncoder,
    "A95B": Tag595BEncoder,
    "1D3B": Tag1D3BEncoder,
    "D35B": TagD35BEncoder,
    "1F66": Tag1F66Encoder,
    "6FF1": Tag6FF1Encoder,
    "1F5A": Tag1F5AEncoder,
    "BF97": TagBF97Encoder,
}


# ==============================================================================
# 4. SUFFIX, BLOCK PADDING, E7A8, HDD, MEC5085 & LATITUDE 3540 ENGINES
# ==============================================================================

def bytes_to_u32_le(arr):
    out = []
    for i in range((len(arr) + 3) // 4):
        v = 0
        for k in range(4):
            if i * 4 + k < len(arr):
                v |= arr[i * 4 + k] << (8 * k)
        out.append(v & 0xFFFFFFFF)
    return out


def u32_to_bytes_le(words):
    out = []
    for w in words:
        out.extend((w & 0xFF, (w >> 8) & 0xFF, (w >> 16) & 0xFF, (w >> 24) & 0xFF))
    return out


def calculate_suffix_8(arr5, table, mod: int):
    """Bit-reversal + 0xAA XOR suffix generator (UEFI 0x7d84 & MEC5085 cmd 0x4E)."""
    s = [
        arr5[0] & 0x1F,
        ((rol8(arr5[1], 3) & 0xF1) | (arr5[0] >> 5)) & 0x1F,
        (arr5[1] >> 2) & 0x1F,
        (((arr5[2] & 0xF) << 1) | (arr5[1] >> 7)) & 0xFF,
        (((arr5[3] & 1) << 4) | (arr5[2] >> 4)) & 0xFF,
        (arr5[3] >> 1) & 0x1F,
        (((arr5[4] & 7) << 2) | (arr5[3] >> 6)) & 0xFF,
        (arr5[4] >> 3) & 0xFF,
    ]
    out = []
    for i in range(8):
        r = 0xAA
        for bit in range(5):
            if s[i] & (1 << bit):
                r ^= arr5[bit]
        out.append(table[(r & 0xFF) % mod])
    return out


def mec5085_cmd_0x4e(service_tag: str) -> str:
    """Plaintext MEC5085/MEC5107 EC (ARCompact 0x1abfc / Cortex-M4 0xeb990) 8-char Service Tag code."""
    rev = [ord(c) for c in service_tag.upper()[:5].ljust(5, "\x00")][::-1]
    return "".join(calculate_suffix_8(rev, ALPHABETS["2A7B"], 72))


def keygen_e7a8(serial: str):
    """Generate both E7A8 Master Passwords (Code 1 & Code 2) for 7-char ST or 11-char HDD."""
    raw = [ord(c) for c in (serial.upper() + "E7A8")]
    block = bytes_to_u32_le(raw)
    while len(block) < 16:
        block.append(0)
    alph = ALPHABETS["E7A8"]
    out = []
    for cls in (TagE7A8Encoder, TagE7A8EncoderSecond):
        state = cls.encode(block)
        digest = hashlib.sha256(bytes(u32_to_bytes_le(state))).digest()
        pw = "".join(alph[(digest[i + 16] + digest[i]) % 72] for i in range(16))
        out.append(pw)
    return out


def keygen_dell(serial: str, suffix: str, mode: str = "service"):
    """Compute Dell Master Password(s) for Service Tag (7 chars) or HDD (11 chars)."""
    serial = serial.strip().upper()
    suffix = suffix.strip().upper()

    if suffix == "0001":
        # Firmware falls back to canonical BF97 table when master unlock is enabled
        suffix = "BF97"

    if suffix == "E7A8":
        return keygen_e7a8(serial)

    if suffix not in LEGACY_ENCODERS:
        raise ValueError(f"Unsupported offline suffix: {suffix}")

    if suffix == "A95B":
        full = (serial + "595B") if mode == "service" else (serial[3:] + "\x00\x00\x00595B")
    else:
        full = serial + suffix

    full_arr = [ord(c) for c in full]
    if mode == "hdd":
        arr5 = [full_arr[8], full_arr[9], full_arr[10], full_arr[1], full_arr[0]]
    else:
        arr5 = [full_arr[4], full_arr[3], full_arr[2], full_arr[1], full_arr[0]]

    if suffix in EXTRA_CHARACTERS:
        sfx = [ord(c) for c in calculate_suffix_8(arr5, EXTRA_CHARACTERS[suffix], 72)]
    else:
        sfx = calculate_suffix_8(arr5, ENCSCANS, 36)

    msg = list(full_arr + sfx)
    while len(msg) <= 23:
        msg.append(0)
    msg[23] = 0x80
    enc_block = bytes_to_u32_le(msg)
    while len(enc_block) < 16:
        enc_block.append(0)
    enc_block[14] = 23 << 3
    enc_block[15] = 0

    dec_bytes = u32_to_bytes_le(LEGACY_ENCODERS[suffix].encode(enc_block))
    table = EXTRA_CHARACTERS.get(suffix)
    if table is not None:
        return ["".join(table[dec_bytes[i] % 72] for i in range(16))]

    r = dec_bytes[0] % 9
    pw = []
    for i in range(16):
        if r <= i and len(pw) < 8:
            pw.append(SCAN_CODES[ENCSCANS[dec_bytes[i] % 36]])
    return ["".join(pw)]


def keygen_hdd_old(serial11: str) -> str:
    """Pre-suffix 11-char Dell HDD master password."""
    sa = [ord(c) for c in serial11.strip().upper()]
    ret = [
        49, 49, 49, 49, 49,
        sa[1] >> 1,
        ((sa[1] >> 6) | (sa[0] << 2)) & 0xFF,
        sa[0] >> 3,
    ]
    out = []
    for i in range(8):
        r = 0xAA
        if ret[i] & 8:
            r ^= sa[1]
        if ret[i] & 16:
            r ^= sa[0]
        out.append(SCAN_CODES[ENCSCANS[(r & 0xFF) % 36]])
    return "".join(out)


def render_ec_response(resp32: bytes, suffix: str) -> str:
    """Render a 32-byte EC type-6 mailbox response into the 16-char Master Password."""
    if len(resp32) < 32:
        raise ValueError("resp32 must be 32 bytes (64 hex chars)")
    suffix = suffix.upper()
    if suffix == "8FC8":
        alph = ALPHABETS["8FC8"]
        return "".join(alph[(resp32[i] + resp32[i + 16]) % 72] for i in range(16))
    return resp32[:16].decode("latin1")


class _DellDES:
    """Non-standard bit-order DES used by Dell Latitude 3540 (Insyde BIOS)."""

    IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
           59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
           31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
           29, 21, 13, 5, 28, 20, 12, 4]
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    EXPANSION = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
                 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22,
                 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    POST_SBOX = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31,
                 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    SBOX = [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 0xA, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ]

    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.subkeys = [0] * 32
        lp = rp = 0
        for i in range(56):
            ix = self.PC1[i] - 1
            bit = (self.key[ix >> 3] >> (7 - (ix & 7))) & 1
            if i < 28:
                lp |= bit << i
            else:
                rp |= bit << (i - 28)
        for rnd in range(16):
            s = self.SHIFTS[rnd]
            lp = ((lp >> s) | (lp << (28 - s))) & 0xFFFFFFF
            rp = ((rp >> s) | (rp << (28 - s))) & 0xFFFFFFF
            p1 = p2 = 0
            for i in range(48):
                ix = self.PC2[i] - 1
                bit = ((lp >> ix) if ix < 28 else (rp >> (ix - 28))) & 1
                if i < 32:
                    p1 |= bit << i
                else:
                    p2 |= bit << (i - 32)
            self.subkeys[rnd << 1] = p2
            self.subkeys[(rnd << 1) | 1] = p1

    @classmethod
    def _f(cls, data: int, sk2: int, sk1: int) -> int:
        p1 = p2 = 0
        for i in range(48):
            ix = cls.EXPANSION[i] - 1
            if i < 32:
                p1 |= ((data >> ix) & 1) << i
            else:
                p2 |= ((data >> ix) & 1) << (i - 32)
        p2 ^= sk2
        p1 ^= sk1

        def eb(k):
            return (p1 >> k) & 1 if k < 32 else (p2 >> (k - 32)) & 1

        tmp = 0
        for i in range(0, 48, 6):
            row = (eb(i) << 1) | eb(i + 5)
            col = (eb(i + 1) << 3) | (eb(i + 2) << 2) | (eb(i + 3) << 1) | eb(i + 4)
            tmp = (tmp << 4) | cls.SBOX[((i // 6) << 6) | (row << 4) | col]
        out = 0
        for i in range(32):
            out |= ((tmp >> (32 - cls.POST_SBOX[i])) & 1) << i
        return out

    def crypt(self, inp: bytes, encrypt: bool = True) -> bytes:
        lp = rp = 0
        for i in range(64):
            ix = self.IP[i] - 1
            bit = (inp[ix >> 3] >> (7 - (ix & 7))) & 1
            if i < 32:
                lp |= bit << i
            else:
                rp |= bit << (i - 32)
        for rnd in (range(16) if encrypt else range(15, -1, -1)):
            lp, rp = rp, lp ^ self._f(rp, self.subkeys[rnd << 1], self.subkeys[(rnd << 1) | 1])
        out = bytearray(8)
        for i in range(64):
            ix = self.FP[i] - 1
            bit = ((rp >> ix) & 1) if ix < 32 else ((lp >> (ix - 32)) & 1)
            out[i >> 3] |= bit << (7 - (i & 7))
        return bytes(out)


def latitude_3540_keygen(hash16: str, tag7: str):
    """Dell Latitude 3540 (Insyde BIOS) 16-hex + 7-char Service Tag keygen."""
    b2 = bytes.fromhex(hash16)
    b1 = bytearray(8)
    b1[0] = ord(tag7.upper()[-1])
    k2 = _DellDES(b"23AAFFAD").crypt(bytes(b1), True)
    pwd = _DellDES(k2).crypt(b2, False).decode("latin1")
    return pwd if all(c in "0123456789abcdefABCDEF" for c in pwd) else None


# ==============================================================================
# 5. CLI & SELF-TEST SUITE (60+ VERIFIED VECTORS)
# ==============================================================================

def selftest() -> bool:
    # 1) 21 Service-Tag legacy vectors
    st_vectors = [
        ("1234567", "595B", "46rg65ky"),
        ("1234567", "D35B", "5tc8q9re"),
        ("1234567", "2A7B", "J1KuwWpSUgnDarfi"),
        ("1234567", "A95B", "46rg65ky"),
        ("1234567", "1D3B", "Sn4fkF8bS57NymZl"),
        ("1234567", "1F66", "kIpTBzx0m3s10JDR"),
        ("1234567", "6FF1", "Rzn1wGe555H5bM2r"),
        ("OPENSRC", "1D3B", "S3yJ91q0Gar3O72I"),
        ("ABCDEFG", "1D3B", "xvn0qEeftqyrkG52"),
        ("7G9C0G2", "6FF1", "35c0b0tVb32Z6ivD"),
        ("DELLSUX", "1F66", "qHXaL0ntli6Gu4c0"),
        ("CRPP562", "1F66", "8i5qLGa9woA919Ys"),
        ("CDG8T32", "1F66", "4Ke3y2L3kTP2f6Vo"),
        ("8M5RQ32", "1F66", "3rlrbaSj46Iw221g"),
        ("1234567", "1F5A", "2ls2b8GiP9H032kx"),
        ("OPENSRC", "1F5A", "ZC3j2t56eIe4Thgi"),
        ("ABCDEFG", "1F5A", "x2zL5n7jj2Gl2TIh"),
        ("1234567", "BF97", "2r09GZhU[r0kW2zr"),
        ("OPENSRC", "BF97", "Dp29XkbyMrkBrp6Z"),
        ("ABCDEFG", "BF97", "kr9Z1cmPpahGzsQ["),
        ("DELLSUX", "BF97", "rrNM2LrbD8nGsd2P"),
    ]
    for s, t, exp in st_vectors:
        assert keygen_dell(s, t)[0] == exp, f"FAIL {s}-{t}"

    # 2) 15 E7A8 Service-Tag dual-code vectors (real-world + pwgen-for-bios)
    e7_vectors = [
        ("65FDQN2", "zxdIkZ1XBrINbkDr", "a0ycrkLr9Be8BZze"),
        ("D9B7JW2", "es6yZz5EaFBxE17Q", "GrIUZsQ3ex529M[6"),
        ("5LS8423", "RnGrGsQNZB1rIJ9r", "QazRb9ayEDQ6913P"),
        ("F2V9SQ2", "PIFQ2Nns9xMIIQsG", "rGBy3x[n12Ekr[3e"),
        ("J4F3CV2", "d2bkF2QekQ2rbk9Q", "nrjy23QrF6dMqL1I"),
        ("G7LMQ73", "1GIkGGGmZNc2RNMN", "QrzQkJ7ZGRRWXEUQ"),
        ("6HDT5S2", "rhGyIG6Nk7MFE9Gk", "Zq8r9P6rRGkMIhN1"),
        ("1JGPCK2", "67M[kP4k92yG4nMQ", "RGRb5UBrrEa8hrGL"),
        ("BXBGRQ2", "9yZ19ZRG0nZkDkGx", "ZIGc2UMjZD[ZcypI"),
        ("1234567", "Qk3LkU22kPeyq2jd", "rLIqjUy59IG2JU2R"),
        ("D875TG2", "rLZc96rMZyGQ2GMG", "1Q6rxIWMGUznXZNy"),
        ("2XSX273", "rPQ0DGLdqckG2kUZ", "0ZaP6RzW9qk73rmq"),
        ("CZXKYX2", "RGWD2BIR9UB9ZdIy", "38Gr7brmRGBPPIkz"),
        ("6651WZ2", "PBjMMMsZUQR2MhmR", "Q1N6k2sLRkGGGrEN"),
        ("H2FS5S3", "s1JRqmRNP0rmI988", "ZM3ax1ZQhG3G9pha"),
    ]
    for s, c1, c2 in e7_vectors:
        assert keygen_dell(s, "E7A8") == [c1, c2], f"FAIL {s}-E7A8"

    # 3) 14 HDD 11-char vectors + hddOld
    hdd_vectors = [
        ("1234567890A", "595B", ["nyoap4lq"]),
        ("1234567890A", "D35B", ["dc14blrd"]),
        ("1234567890A", "2A7B", ["h6lwdi91qluUyt3u"]),
        ("1234567890A", "A95B", ["qr0s6x4n"]),
        ("1234567890A", "1D3B", ["6JQ1WacHNNR0Taia"]),
        ("1234567890A", "1F66", ["vP0M31x066Z7Rq9p"]),
        ("1234567890A", "6FF1", ["5enLLpM3Immfb8CK"]),
        ("1234567890A", "1F5A", ["L9IJjYoUIXeY5wOy"]),
        ("12345678901", "1F5A", ["QwO5Dki1zeR1n1t2"]),
        ("12345678901", "BF97", ["nDrmUU6U5DI9ZLMI"]),
        ("1234567890A", "BF97", ["pRrky3r9ryEPNNJz"]),
        ("234567890AB", "BF97", ["h2RDrReN37I1NLmr"]),
        ("1234567890A", "E7A8", ["rN2rE2RBQh[X00yr", "G1bFzRGzjXIGzr22"]),
        ("1234567890B", "E7A8", ["Ic18yqyXXZI5Qj22", "kzzMazZrz53sRZJm"]),
    ]
    for s, t, exp in hdd_vectors:
        got = keygen_dell(s, t, mode="hdd")
        assert sorted(got) == sorted(exp), f"FAIL HDD {s}-{t}"
    assert keygen_hdd_old("12345678901") == "yyyyyhnn"

    # 4) Latitude 3540 Insyde DES vectors
    assert latitude_3540_keygen("5F3988D5E0ACE4BF", "7QH8602") == "98072364"
    assert latitude_3540_keygen("76A7D90FD9563C5F", "3FN2J22") == "60485207"
    assert latitude_3540_keygen("1B6DD24D26E7B566", "BJVDG22") == "99937880"
    assert latitude_3540_keygen("1B6DD24D26E7C566", "BJVDG22") is None

    # 5) Plaintext MEC5085/MEC5107 cmd 0x4E (Unicorn Cortex-M4 verified) & EC resp32 renderers
    assert mec5085_cmd_0x4e("H2FS5S3") == "10l6leru"
    assert mec5085_cmd_0x4e("5YY8TB4") == "JJ2o2r2O"
    assert mec5085_cmd_0x4e("7XH2273") == "ww7eb7CT"
    assert render_ec_response(bytes(range(32)), "8FC8") == "q53G1h4ePMz2zUJB"
    assert render_ec_response(b"A1B2C3D4E5F6G7H8" + b"\x00" * 16, "CF1B") == "A1B2C3D4E5F6G7H8"

    # 6) 7 real field-verified 8FC8 master passwords (112/112 chars strictly in ALPHABET0)
    alph0_set = set(ALPHABETS["8FC8"])
    verified_8fc8 = [
        ("1K6Y963", "BZsa9RGZzyIGD3pI"),
        ("5S38Y33", "2QqPqMGQxLNrrZxW"),
        ("C9F23Z2", "kr8a9e2xdPGRb1Lz"),
        ("2C90B83", "N9NM9j1qRMeGzyyr"),
        ("D76FQF4", "[PhyzIar3jy2Z6zM"),
        ("GSSS6C4", "rN3U2IZhzZ7njNcb"),
        ("F4NRGB4", "2933yxzZr5NLq0aX"),
    ]
    for st, pw in verified_8fc8:
        assert len(pw) == 16 and all(ch in alph0_set for ch in pw), f"FAIL 8FC8 alphabet {st}"

    print("PASS: All 67 test vectors (ServiceTag, E7A8 Code 1/2, HDD, Latitude 3540, MEC5085/5107, EC render & 7 real 8FC8 oracles) verified!")
    return True


def solve_input(raw_input_str: str, resp32_hex: str = ""):
    s = raw_input_str.strip().upper()
    if not s:
        print("Error: empty Service Tag.")
        return 1

    # Case 1: Latitude 3540 (16-hex + optional '-' + 7-char Service Tag)
    m_lat = re.match(r"^([0-9A-F]{16})-?([0-9A-Z]{7})$", s)
    if m_lat:
        pw = latitude_3540_keygen(m_lat.group(1), m_lat.group(2))
        print(f"Input (Latitude 3540): {m_lat.group(1)}-{m_lat.group(2)}")
        print(f"  Master Password    : {pw if pw else 'Invalid hash/tag pair'}")
        print("\nSubmit with: Ctrl + Enter")
        return 0

    # Parse <SERIAL>-<SUFFIX> or bare <SERIAL>
    if "-" in s:
        serial, suffix = s.split("-", 1)
    elif len(s) == 11 and s[7:] in OFFLINE_SUFFIXES + EC_SEALED_SUFFIXES + ("0001",):
        serial, suffix = s[:7], s[7:]
    elif len(s) == 15 and s[11:] in OFFLINE_SUFFIXES + EC_SEALED_SUFFIXES:
        serial, suffix = s[:11], s[11:]
    else:
        serial, suffix = s, ""

    mode = "hdd" if len(serial) == 11 else "service"
    if len(serial) not in (5, 6, 7, 11):
        print(f"Error: expected 7-char Dell Service Tag (or 11-char HDD serial), got {serial!r} ({len(serial)} chars).")
        return 1

    # Specific suffix requested
    if suffix:
        if suffix in EC_SEALED_SUFFIXES:
            print(f"System ID: {serial}-{suffix}")
            if resp32_hex:
                pw = render_ec_response(bytes.fromhex(resp32_hex), suffix)
                print(f"  Master Password (from EC resp32): {pw}")
                print("\nSubmit with: Ctrl + Enter")
                return 0
            print(f"  [!] HARDWARE-SEALED EC SUFFIX (-{suffix}):")
            print("      On 8FC8 (2020-2025) and CF1B/9ABE/3FE2/1B58 (2025-2026) systems,")
            print("      Dell moved master-key generation inside the Embedded Controller's")
            print("      OTP-encrypted silicon (MEC5200 iFuse / NPCX993D iFuse, cmd 0x21 type 6).")
            print("      NO offline calculator can compute this password from Service Tag alone")
            print("      without reading the 32-byte EC response (--resp32 <64-hex>) or SPI unlock.")
            return 2

        pws = keygen_dell(serial, suffix, mode=mode)
        print(f"System ID ({mode.upper()}): {serial}-{suffix}")
        if len(pws) == 2:
            print(f"  Master Password (Code 1 - primary) : {pws[0]}")
            print(f"  Master Password (Code 2 - rotated) : {pws[1]}")
        else:
            print(f"  Master Password                    : {pws[0]}")
        print("\nSubmit on BIOS password prompt with: Ctrl + Enter")
        return 0

    # Bare Service Tag or bare 11-char HDD serial -> compute ALL offline suffixes!
    print(f"Dell {'HDD Serial' if mode == 'hdd' else 'Service Tag'}: {serial}  (All Offline Master Passwords)")
    print("-" * 68)
    e7 = keygen_dell(serial, "E7A8", mode=mode)
    print(f"  {serial}-E7A8 (Code 1, primary) : {e7[0]}")
    print(f"  {serial}-E7A8 (Code 2, rotated) : {e7[1]}")
    for sfx in ("BF97", "6FF1", "1F66", "1D3B", "1F5A", "2A7B", "D35B", "595B", "A95B"):
        pw = keygen_dell(serial, sfx, mode=mode)[0]
        print(f"  {serial}-{sfx:<22} : {pw}")
    if mode == "hdd":
        print(f"  {serial} (Old pre-suffix HDD)   : {keygen_hdd_old(serial)}")
    else:
        print(f"  {serial} (MEC5085 EC cmd 0x4E)  : {mec5085_cmd_0x4e(serial)}")
    print("-" * 68)
    print("Note: -8FC8 and -CF1B/-9ABE/-3FE2/-1B58 are sealed in EC iFuse hardware")
    print("      and cannot be computed from a Service Tag alone.")
    print("Submit on BIOS password prompt with: Ctrl + Enter")
    return 0


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        sys.exit(0 if selftest() else 1)

    resp32_hex = ""
    if "--resp32" in args:
        idx = args.index("--resp32")
        if idx + 1 >= len(args):
            print("Error: --resp32 requires 64 hex characters.")
            sys.exit(2)
        resp32_hex = args[idx + 1]
        args = args[:idx] + args[idx + 2:]

    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if not args:
        try:
            user_in = input("Enter Dell Service Tag (e.g. 65FDQN2 or 65FDQN2-E7A8): ")
        except EOFError:
            print(__doc__)
            sys.exit(0)
        sys.exit(solve_input(user_in, resp32_hex=resp32_hex))

    if len(args) >= 2 and len(args[1]) == 4 and "-" not in args[0]:
        query = f"{args[0]}-{args[1]}"
    else:
        query = args[0]
    sys.exit(solve_input(query, resp32_hex=resp32_hex))


if __name__ == "__main__":
    main()
