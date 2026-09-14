#!/usr/bin/env python3
"""Dell legacy-suffix BIOS master password generator.

Computes Dell BIOS master passwords from a service tag for the legacy
suffix families that have public keygen algorithms: 595B, 2A7B, A95B,
D35B, 1D3B, 1F5A, 1F66, 6FF1, BF97 and E7A8.

FC1B / CF1B / 8FC8 machines have NO public service-tag algorithm: their
BIOS password is verified inside the firmware. Use the BIOS dump patch
procedure (tools/dell_fc1b_unlock.py) for those suffixes.

Algorithm ported from the public generators (Dogbert's Dell keygen as
shipped in github.com/chromebreakerdev/DellBIOSTools). Public test
vector: DELLSUX-1F66 -> qHXaL0ntli6Gu4c0.

Usage:
    python3 dell_keygen.py ABC1234-1F66
    python3 dell_keygen.py ABC1234 595B
    python3 dell_keygen.py --self-test
"""

from __future__ import annotations

import hashlib
import sys
from typing import Dict, List

# ---------------------------------------------------------------------------
# MD5-derived tables used by the Dell encoders
# ---------------------------------------------------------------------------

md5magic = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
]

md5magic2 = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
]

rotationTable = [
    [7, 12, 17, 22],
    [5, 9, 14, 20],
    [4, 11, 16, 23],
    [6, 10, 15, 21],
]

initialData = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# ---------------------------------------------------------------------------
# 32-bit primitives
# ---------------------------------------------------------------------------


def mask32(x: int) -> int:
    return x & 0xFFFFFFFF


def rol(x: int, bits: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << bits) & 0xFFFFFFFF) | (x >> (32 - bits))


def encF1(num1: int, num2: int) -> int:
    return (num1 + num2) & 0xFFFFFFFF


def encF1N(num1: int, num2: int) -> int:
    return (num1 - num2) & 0xFFFFFFFF


def encF2(num1: int, num2: int, num3: int) -> int:
    return ((num3 ^ num2) & num1) ^ num3


def encF2N(num1: int, num2: int, num3: int) -> int:
    return encF2(num1, num2, (~num3) & 0xFFFFFFFF)


def encF3(num1: int, num2: int, num3: int) -> int:
    return ((num1 ^ num2) & num3) ^ num2


def encF4(num1: int, num2: int, num3: int) -> int:
    return (num2 ^ num1) ^ num3


def encF4N(num1: int, num2: int, num3: int) -> int:
    return encF4(num1, (~num2) & 0xFFFFFFFF, num3)


def encF5(num1: int, num2: int, num3: int) -> int:
    return (num1 | ((~num3) & 0xFFFFFFFF)) ^ num2


def encF5N(num1: int, num2: int, num3: int) -> int:
    return encF5((~num1) & 0xFFFFFFFF, num2, num3)


# ---------------------------------------------------------------------------
# Per-suffix encoders
# ---------------------------------------------------------------------------


class Tag595BEncoder:
    f1 = staticmethod(encF1N)
    f2 = staticmethod(encF2N)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4N)
    f5 = staticmethod(encF5N)
    md5table = md5magic

    def __init__(self, encBlock: List[int]):
        self.encBlock = encBlock
        self.encData = self.initialData()
        self.A = self.encData[0]
        self.B = self.encData[1]
        self.C = self.encData[2]
        self.D = self.encData[3]

    @classmethod
    def encode(cls, encBlock: List[int]) -> List[int]:
        obj = cls(encBlock)
        obj.makeEncode()
        return obj.result()

    def makeEncode(self) -> None:
        for i in range(64):
            which = i >> 4
            if which == 0:
                t = self.calculate(self.f2, (i & 15), i)
            elif which == 1:
                t = self.calculate(self.f3, ((i * 5 + 1) & 15), i)
            elif which == 2:
                t = self.calculate(self.f4, ((i * 3 + 5) & 15), i)
            else:
                t = self.calculate(self.f5, ((i * 7) & 15), i)
            self.A, self.D, self.C = self.D, self.C, self.B
            shift = rotationTable[which][(i & 3)]
            self.B = mask32(self.B + rol(t, shift))
        self.incrementData()

    def initialData(self) -> List[int]:
        return initialData[:]

    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.B, self.C, self.D)
        combined = (self.md5table[key2] + self.encBlock[key1]) & 0xFFFFFFFF
        return (self.A + self.f1(tmp, combined)) & 0xFFFFFFFF

    def incrementData(self) -> None:
        self.encData[0] = mask32(self.encData[0] + self.A)
        self.encData[1] = mask32(self.encData[1] + self.B)
        self.encData[2] = mask32(self.encData[2] + self.C)
        self.encData[3] = mask32(self.encData[3] + self.D)

    def result(self) -> List[int]:
        return [mask32(x) for x in self.encData]


class TagD35BEncoder(Tag595BEncoder):
    f1 = staticmethod(encF1)
    f2 = staticmethod(encF2)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4)
    f5 = staticmethod(encF5)


class Tag1D3BEncoder(Tag595BEncoder):
    def makeEncode(self) -> None:
        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= (0x60606161 - j) & 0xFFFFFFFF
            self.D ^= (0x50501010 + j) & 0xFFFFFFFF
            super().makeEncode()


class Tag1F66Encoder(Tag595BEncoder):
    md5table = md5magic2

    def makeEncode(self) -> None:
        for j in range(17):
            self.A |= 0x100097
            self.B ^= 0xA0008
            self.C |= (0x60606161 - j) & 0xFFFFFFFF
            self.D ^= (0x50501010 + j) & 0xFFFFFFFF
            for i in range(64):
                which = i >> 4
                if which == 0:
                    t = self.calculate(self.f2, (i & 15), (i + 16) & 0xFFFFFFFF)
                elif which == 1:
                    t = self.calculate(self.f3, ((i * 5 + 1) & 15), (i + 32) & 0xFFFFFFFF)
                elif which == 2:
                    offset = i - 2 * (i & 12) + 12
                    t = self.calculate(self.f4, ((i * 3 + 5) & 15), offset)
                else:
                    offset = 2 * (i & 3) - (i & 15) + 12
                    t = self.calculate(self.f5, ((i * 7) & 15), offset)
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[which][(i & 3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()
        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= (0x50501010 - j) & 0xFFFFFFFF
            self.D ^= (0x60606161 + j) & 0xFFFFFFFF
            for i in range(64):
                which = i >> 4
                if which == 0:
                    offset = 2 * (i & 3) - i + 44
                    t = self.calculate(self.f4, ((i * 3 + 5) & 15), offset)
                elif which == 1:
                    offset = 2 * (i & 3) - i + 76
                    t = self.calculate(self.f5, ((i * 7) & 15), offset)
                elif which == 2:
                    offset = (i & 15)
                    t = self.calculate(self.f2, (i & 15), offset)
                else:
                    offset = (i - 32) & 0xFFFFFFFF
                    t = self.calculate(self.f3, ((i * 5 + 1) & 15), offset)
                g = ((i >> 4) + 2) & 3
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[g][(i & 3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()


class Tag6FF1Encoder(Tag595BEncoder):
    md5table = md5magic2
    counter1 = 23

    def makeEncode(self) -> None:
        for j in range(self.counter1):
            self.A |= 0xA08097
            self.B ^= 0xA010908
            self.C |= (0x60606161 - j) & 0xFFFFFFFF
            self.D ^= (0x50501010 + j) & 0xFFFFFFFF
            for i in range(64):
                which = i >> 4
                k = (i & 15) - ((i & 12) << 1) + 12
                if which == 0:
                    t = self.calculate(self.f2, (i & 15), (i + 32) & 0xFFFFFFFF)
                elif which == 1:
                    t = self.calculate(self.f3, ((i * 5 + 1) & 15), (i & 15))
                elif which == 2:
                    t = self.calculate(self.f4, ((i * 3 + 5) & 15), (k + 16) & 0xFFFFFFFF)
                else:
                    t = self.calculate(self.f5, ((i * 7) & 15), (k + 48) & 0xFFFFFFFF)
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[which][(i & 3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()
        for j in range(17):
            self.A |= 0x100097
            self.B ^= 0xA0008
            self.C |= (0x50501010 - j) & 0xFFFFFFFF
            self.D ^= (0x60606161 + j) & 0xFFFFFFFF
            for i in range(64):
                which = i >> 4
                k = (i & 15) - ((i & 12) << 1) + 12
                if which == 0:
                    shiftval = ((i & 15) * 3 + 5) & 15
                    t = self.calculate(self.f4, shiftval, (k + 16))
                elif which == 1:
                    shiftval = ((i & 3) * 7 + (i & 12) + 4) & 15
                    t = self.calculate(self.f5, shiftval, ((i & 15) + 32) & 0xFFFFFFFF)
                elif which == 2:
                    t = self.calculate(self.f2, (k & 15), k)
                else:
                    shiftval = ((i & 15) * 5 + 1) & 15
                    t = self.calculate(self.f3, shiftval, ((i & 15) + 48) & 0xFFFFFFFF)
                g = ((i >> 4) + 2) & 3
                self.A, self.D, self.C = self.D, self.C, self.B
                shift = rotationTable[g][(i & 3)]
                self.B = mask32(self.B + rol(t, shift))
            self.incrementData()


class Tag1F5AEncoder(Tag595BEncoder):
    md5table = md5magic2

    def makeEncode(self) -> None:
        for _ in range(5):
            for j in range(64):
                k = 12 + (j & 3) - (j & 12)
                which = j >> 4
                if which == 0:
                    t = self.calculate(self.f2, j & 15, j)
                elif which == 1:
                    t = self.calculate(self.f3, ((j * 5 + 1) & 15), j)
                elif which == 2:
                    t = self.calculate(self.f4, ((j * 3 + 5) & 15), (k + 0x20) & 0xFFFFFFFF)
                else:
                    t = self.calculate(self.f5, ((j * 7) & 15), (k + 0x30) & 0xFFFFFFFF)
                self.B, self.D, self.A = self.D, self.A, self.C
                shift = rotationTable[which][(j & 3)]
                self.C = mask32(self.C + rol(t, shift))
            self.incrementData()

    def incrementData(self) -> None:
        self.encData[0] = mask32(self.encData[0] + self.B)
        self.encData[1] = mask32(self.encData[1] + self.C)
        self.encData[2] = mask32(self.encData[2] + self.A)
        self.encData[3] = mask32(self.encData[3] + self.D)

    def calculate(self, func, key1: int, key2: int) -> int:
        tmp = func(self.C, self.A, self.D)
        combined = (self.md5table[key2] + self.encBlock[key1]) & 0xFFFFFFFF
        return (self.B + encF1(tmp, combined)) & 0xFFFFFFFF


class TagBF97Encoder(Tag6FF1Encoder):
    counter1 = 31


class TagE7A8Encoder(Tag595BEncoder):
    md5table = md5magic2
    loopParams = [17, 13, 12, 8]
    encodeParams = [
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008, 0x100097, 0x50501010,
    ]

    def initialData(self) -> List[int]:
        return [0, 0, 0, 0]

    def makeEncode(self) -> None:
        for p in range(self.loopParams[0]):  # 17
            self.A |= self.encodeParams[0]
            self.B ^= self.encodeParams[1]
            self.C |= (self.encodeParams[2] - p) & 0xFFFFFFFF
            self.D ^= (self.encodeParams[3] + p) & 0xFFFFFFFF
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f2, j, j + 32, 0, [0, 1, 2, 3])
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f3, j, j, 1, [1, -2, -1, 0])
            for j in range(self.loopParams[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(self.loopParams[3], 3, -4):
                self.shortcut(self.f5, j, j + 48, 3, [2, 3, 2, -3])
            self.incrementData()
        for p in range(self.loopParams[1]):  # 13
            self.A |= self.encodeParams[4]
            self.B ^= self.encodeParams[5]
            self.C |= (self.encodeParams[6] - p) & 0xFFFFFFFF
            self.D ^= (self.encodeParams[7] + p) & 0xFFFFFFFF
            for j in range(self.loopParams[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f5, j, j + 32, 3, [2, 3, 2, -3])
            for j in range(self.loopParams[3], 0, -4):
                self.shortcut(self.f2, j, j, 0, [0, 1, 2, 3])
            for j in range(0, self.loopParams[2], 4):
                self.shortcut(self.f3, j, j + 48, 1, [1, -2, 3, 0])
            self.incrementData()

    def shortcut(self, fun, j, md5_index, rot_index, indexes):
        for i in range(4):
            t = self.calculate(fun, (j + indexes[i]) & 7, md5_index + i)
            self.A, self.D, self.C = self.D, self.C, self.B
            shift = rotationTable[rot_index][i]
            self.B = (self.B + rol(t, shift)) & 0xFFFFFFFF


class TagE7A8EncoderSecond(TagE7A8Encoder):
    def __init__(self, encBlock: List[int]):
        super().__init__(encBlock)
        overfillArr = [
            (0xA0008 ^ 0x6D2F93A5),
            (0xA08097 ^ 0x6D2F93A5),
            (0xA010908 ^ 0x6D2F93A5),
            (0x60606161 ^ 0x6D2F93A5),
        ]
        extended = md5magic2[:] + overfillArr
        self.md5table = extended
        self.loopParams = [17, 13, 12, 16]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

SUPPORTED_SUFFIXES = ("595B", "D35B", "2A7B", "A95B", "1D3B", "1F66", "6FF1", "1F5A", "BF97", "E7A8")
NO_KEYGEN_SUFFIXES = ("FC1B", "CF1B", "8FC8")  # firmware-verified: use the BIOS dump patch instead

encoders: Dict[str, object] = {
    "595B": Tag595BEncoder,
    "2A7B": Tag595BEncoder,
    "A95B": Tag595BEncoder,
    "1D3B": Tag1D3BEncoder,
    "D35B": TagD35BEncoder,
    "1F66": Tag1F66Encoder,
    "6FF1": Tag6FF1Encoder,
    "1F5A": Tag1F5AEncoder,
    "BF97": TagBF97Encoder,
    "E7A8": TagE7A8Encoder,
}

scanCodes = (
    "\0\x1B1234567890-=\x08\x09"
    "qwertyuiop[]\x0D\xFF"
    "asdfghjkl;'`\xFF\\"
    "zxcvbnm,./"
)
encscans = [
    0x05, 0x10, 0x13, 0x09, 0x32, 0x03, 0x25, 0x11, 0x1F, 0x17, 0x06, 0x15,
    0x30, 0x19, 0x26, 0x22, 0x0A, 0x02, 0x2C, 0x2F, 0x16, 0x14, 0x07, 0x18,
    0x24, 0x23, 0x31, 0x20, 0x1E, 0x08, 0x2D, 0x21, 0x04, 0x0B, 0x12, 0x2E,
]
asciiPrintable = "012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
extraCharacters = {
    "2A7B": asciiPrintable,
    "1F5A": asciiPrintable,
    "1D3B": "0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0",
    "1F66": "0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0",
    "6FF1": "08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0",
    "BF97": "0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ",
}


def blockEncode(encBlock: List[int], tag: str) -> List[int]:
    if tag not in encoders:
        raise ValueError(f"Unknown tag: {tag}")
    klass = encoders[tag]
    return klass.encode(encBlock)


def byteArrayToInt(arr: List[int]) -> List[int]:
    resultLength = len(arr) >> 2
    out = []
    for i in range(resultLength + 1):
        val = 0
        if i * 4 < len(arr):
            val |= arr[i * 4]
        if i * 4 + 1 < len(arr):
            val |= (arr[i * 4 + 1] << 8)
        if i * 4 + 2 < len(arr):
            val |= (arr[i * 4 + 2] << 16)
        if i * 4 + 3 < len(arr):
            val |= (arr[i * 4 + 3] << 24)
        val &= 0xFFFFFFFF
        out.append(val)
    return out


def intArrayToByte(arr: List[int]) -> List[int]:
    out = []
    for num in arr:
        out.append(num & 0xFF)
        out.append((num >> 8) & 0xFF)
        out.append((num >> 16) & 0xFF)
        out.append((num >> 24) & 0xFF)
    return out


def calculateSuffix(serial: List[int], tag: str) -> List[int]:
    arr1 = [1, 2, 3, 4]
    arr2 = [4, 3, 2]
    suffix = [0] * 8
    suffix[0] = serial[arr1[3]]
    suffix[1] = (serial[arr1[3]] >> 5) | (((serial[arr1[2]] >> 5) | (serial[arr1[2]] << 3)) & 0xF1)
    suffix[2] = serial[arr1[2]] >> 2
    suffix[3] = (serial[arr1[2]] >> 7) | (serial[arr1[1]] << 1)
    suffix[4] = (serial[arr1[1]] >> 4) | (serial[arr1[0]] << 4)
    suffix[5] = serial[1] >> 1
    suffix[6] = (serial[1] >> 6) | (serial[0] << 2)
    suffix[7] = serial[0] >> 3
    for i in range(8):
        suffix[i] &= 0xFF
    table = extraCharacters.get(tag)
    codesTable = [ord(c) for c in table] if table is not None else encscans
    for i in range(8):
        r = 0xAA
        if suffix[i] & 1:
            r ^= serial[arr2[0]]
        if suffix[i] & 2:
            r ^= serial[arr2[1]]
        if suffix[i] & 4:
            r ^= serial[arr2[2]]
        if suffix[i] & 8:
            r ^= serial[1]
        if suffix[i] & 16:
            r ^= serial[0]
        suffix[i] = codesTable[r % len(codesTable)]
    return suffix


def resultToString(arr: List[int], tag: str) -> str:
    r = arr[0] % 9
    result = ""
    table = extraCharacters.get(tag)
    for i in range(16):
        if table is not None:
            result += table[arr[i] % len(table)]
        else:
            if r <= i and len(result) < 8:
                idx = arr[i] % len(encscans)
                scan_char_idx = encscans[idx]
                if scan_char_idx < len(scanCodes):
                    result += scanCodes[scan_char_idx]
    return result


def calculateE7A8(block: List[int], klass) -> str:
    table = "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"
    encoded_32 = klass.encode(block)
    res_bytes = intArrayToByte(encoded_32)
    digest = hashlib.sha256(bytes(res_bytes)).digest()
    out_str = ""
    for i in range(16):
        idx = (digest[i + 16] + digest[i]) % len(table)
        out_str += table[idx]
    return out_str


def keygenDell(serial: str, tag: str) -> List[str]:
    fullSerial = (serial + "595B") if tag == "A95B" else (serial + tag)
    fullSerialArray = [ord(c) for c in fullSerial]
    if tag == "E7A8":
        encBlock = byteArrayToInt(fullSerialArray)
        for i in range(16):
            if i >= len(encBlock):
                encBlock.append(0)
        out_str1 = calculateE7A8(encBlock, TagE7A8Encoder)
        out_str2 = calculateE7A8(encBlock, TagE7A8EncoderSecond)
        results = []
        if out_str1:
            results.append(out_str1)
        if out_str2:
            results.append(out_str2)
        return results
    suffix = calculateSuffix(fullSerialArray, tag)
    fullSerialArray += suffix
    cnt = 23
    if len(fullSerialArray) <= cnt:
        fullSerialArray += [0] * (cnt - len(fullSerialArray) + 1)
    fullSerialArray[cnt] = 0x80
    encBlock = byteArrayToInt(fullSerialArray)
    for i in range(16):
        if i >= len(encBlock):
            encBlock.append(0)
    encBlock[14] = (cnt << 3)
    decodedBytes = intArrayToByte(blockEncode(encBlock, tag))
    outputResult = resultToString(decodedBytes, tag)
    return [outputResult] if outputResult else []


def parse_input(value: str) -> tuple[str, str]:
    """Accept SERIAL-SUFFIX, SERIAL SUFFIX, or SERIALSUFFIX (11 chars)."""
    cleaned = value.strip().upper().replace(" ", "-")
    if "-" in cleaned:
        serial, _, tag = cleaned.partition("-")
    else:
        if len(cleaned) != 11:
            raise ValueError("input must look like ABC1234-595B (7-char service tag + suffix)")
        serial, tag = cleaned[:7], cleaned[7:]
    serial = serial.strip()
    tag = tag.strip().replace("-", "")
    if len(serial) != 7 or not serial.isalnum():
        raise ValueError("service tag must be exactly 7 alphanumeric characters")
    if tag not in SUPPORTED_SUFFIXES:
        if tag in NO_KEYGEN_SUFFIXES:
            raise ValueError(
                f"the {tag} suffix has no public service-tag keygen "
                "(password is verified in firmware); use the BIOS dump patch procedure "
                "(tools/dell_fc1b_unlock.py) or Dell support with proof of ownership"
            )
        raise ValueError(
            "unsupported suffix; supported legacy suffixes: " + ", ".join(SUPPORTED_SUFFIXES)
        )
    return serial, tag


def self_test() -> None:
    """Validate against the public DELLSUX-1F66 -> qHXaL0ntli6Gu4c0 vector."""
    expected = "qHXaL0ntli6Gu4c0"
    got = keygenDell("DELLSUX", "1F66")
    assert got and got[0] == expected, f"self-test failed: expected {expected!r}, got {got!r}"
    for suffix in SUPPORTED_SUFFIXES:
        out = keygenDell("DELLSUX", suffix)
        assert out and all(out), f"keygen produced empty result for {suffix}"
    print(f"self-test OK: DELLSUX-1F66 -> {got[0]} (all {len(SUPPORTED_SUFFIXES)} suffixes generate)")


def main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[1] == "--self-test":
        self_test()
        return 0
    try:
        serial, tag = parse_input(argv[1])
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    passwords = keygenDell(serial, tag)
    print(f"Dell master password for service tag {serial}-{tag}:")
    for pwd in passwords:
        print(f"  {pwd}")
    if tag == "E7A8":
        print("note: E7A8 yields two candidates; try both.")
    if tag == "6FF1":
        print("note: 6FF1 has a known generator bug; if the password fails, try the same tag with the BF97 suffix.")
    print("enter the password at the BIOS lock screen, then Ctrl+Enter+Enter on models that need it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
