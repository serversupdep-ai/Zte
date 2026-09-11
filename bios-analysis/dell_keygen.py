#!/usr/bin/env python3
"""Dell BIOS master-password keygen — firmware-derived (OptiPlex 3090 BIOS 2.0.7/2.27.0,
Latitude 5X00/5X90/5300 password module: FFS driver w/ PDB 8bfd0c84...pdb).

Reverse-engineered algorithm for the modern lockout families (8FC8-era BIOS with
family value not in the module's {8FC8, E7A8} table — i.e. the CF1B generation).

Findings (pw module disassembly):
  * The lockout suffix (e.g. "CF1B") is a per-machine NVRAM config value
    (u16 at config+0x0A, hex-formatted for display). It is NOT an entry of the
    module's family dispatch table.
  * Dispatch (fn @0x926c, called with out_len=16, map_flag=1):
      - family 0x8FC8/0xE7A8  -> descriptor/SHA-256 path (E7A8 only; 8FC8 stub)
      - anything else (CF1B!) -> legacy fallback @0x92b9:
            data   = ServiceTag(7) + "BF97"
            suffix = calculateSuffix(tag)   # 8 chars, mapped %72 via T72
            block  = data + suffix (19B) zero-padded to 23, MD5-style pad
                     (byte[23]=0x80, bitcount 184 in u32[14])
            enc    = TagBF97Encoder.encode(block)   # == public Tag6FF1 counter1=31
            pw     = ''.join(T72[b % 72] for b in enc16)   # 16 chars
  * T72 = first 72 chars of the 78-byte table at .data RVA 0xAB50.

The legacy BF97 transform in firmware (0x4ce8) was verified equivalent to the
public chromebreakerdev/DellBIOSTools TagBF97Encoder: identical outer constants
(A|=0xA08097, B^=0xA010908, C|=(0x60606161-j), D^=(0x50501010+j)), MD5 rotation
table, encF1N/F2N/F3/F4N/F5N boolean functions, md5magic2 K-table (stored in
firmware XOR 0x6d2f93a5 at .data RVA 0xA150), MD5 IV init and MD5-style padding.

Usage:
    python3 dell_keygen.py H2FS5S3 CF1B        # firmware CF1B path (primary)
    python3 dell_keygen.py <tag> <suffix> --all
    python3 dell_keygen.py --selftest          # E7A8 cross-validation vs public tool
    python3 dell_keygen.py --interpret8fc8 <64+hex>   # render cmd-0x21 mailbox
                                                # response (see dell_8fc8_probe.c)
"""
import sys
import hashlib

# ---------------------------------------------------------------- public tables
md5magic = [
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

md5magic2 = [
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

rotationTable = [[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]]
initialData = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

# firmware table @ RVA 0xAB50 (raw 0x9550), 78 bytes, used with % 72
TABLE_9550 = ("0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2a"
              "BXIjbkGZ2A7B")
T72 = TABLE_9550[:72]

# E7A8 alphabet @ RVA 0xA300 (raw 0x8d00)
E7A8_TABLE = "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"

# ----------------------------------------------------------------------------
# THE SEVEN-TABLE BANK (REPORT §13.12)
# Every alphabet-bearing pw module in the corpus (90 modules, 26 collections,
# OptiPlex 3040 1.20.1 -> 7090/XE4 1.42.0) carries these SEVEN identical
# 72-char tables in .data; the family is selected at runtime by dispatch.
# RVA column = 2.0.7 pw_42k (2.27.0 pw_43k differs by <= 0x10 from 0xAA20 on).
# The 8FC8 table is absent from every public tool (Rex98 GUI v1.0 included,
# §13.13): same 72-char multiset as BF97, fresh permutation.
# ----------------------------------------------------------------------------
TABLE_BANK = {
    "8FC8": ("0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r", 0xA280),
    "E7A8": ("Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ", 0xA300),
    "2A7B": ("012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0", 0xAA10),
    "1D3B": ("0BfIUG1kuPvc8A9Nl5DLZYSno7Ka6HMgqsJWm65yCQR94b21OTp7VFX2z0jihE33d4xtrew0", 0xAA60),
    "1F66": ("0ewr3d4xtUG1ku0BfIp7VFb21OTSno7KDLZYqsJWa6HMgCQR94m65y9Nl5Pvc8AjihE3X2z0", 0xAAB0),
    "6FF1": ("08rptBxfbGVMz38IiSoeb360MKcLf4QtBCbWVzmH5wmZUcRR5DZG2xNCEv1nFtzsZB2bw1X0", 0xAB00),
    "BF97": ("0Q2drGk99rkQFMxN[Z5y3DGr16h638myIL2rzz2pzcU7JWLJ1EGnqRN4seZPRM2aBXIjbkGZ", 0xAB50),
    # 1F5A shares 2A7B's asciiPrintable table (public tools: extraCharacters)
    "1F5A": ("012345679abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0", 0xAA10),
}


def table_for(suffix):
    """Return the 72-char output alphabet for a 4-char family suffix
    (e.g. 'BF97', 'E7A8', '8FC8'). Raises KeyError for unknown families."""
    return TABLE_BANK[suffix.upper()][0]


def mask32(x):
    return x & 0xFFFFFFFF


def rol(x, bits):
    x &= 0xFFFFFFFF
    return ((x << bits) & 0xFFFFFFFF) | (x >> (32 - bits))


def rol8(x, bits):
    x &= 0xFF
    return ((x << bits) | (x >> (8 - bits))) & 0xFF


def encF1(a, b):
    return (a + b) & 0xFFFFFFFF


def encF1N(a, b):
    return (a - b) & 0xFFFFFFFF


def encF2(a, b, c):
    return ((c ^ b) & a) ^ c


def encF2N(a, b, c):
    return encF2(a, b, (~c) & 0xFFFFFFFF)


def encF3(a, b, c):
    return ((a ^ b) & c) ^ b


def encF4(a, b, c):
    return (b ^ a) ^ c


def encF4N(a, b, c):
    return encF4(a, (~b) & 0xFFFFFFFF, c)


def encF5(a, b, c):
    return (a | ((~c) & 0xFFFFFFFF)) ^ b


def encF5N(a, b, c):
    return encF5((~a) & 0xFFFFFFFF, b, c)


class Tag595BEncoder:
    f1 = staticmethod(encF1N)
    f2 = staticmethod(encF2N)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4N)
    f5 = staticmethod(encF5N)
    md5table = md5magic

    def __init__(self, encBlock):
        self.encBlock = encBlock
        self.encData = self.initialData()
        self.A, self.B, self.C, self.D = self.encData

    @classmethod
    def encode(cls, encBlock):
        obj = cls(encBlock)
        obj.makeEncode()
        return obj.result()

    def makeEncode(self):
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

    def initialData(self):
        return initialData[:]

    def calculate(self, func, key1, key2):
        tmp = func(self.B, self.C, self.D)
        combined = (self.md5table[key2] + self.encBlock[key1]) & 0xFFFFFFFF
        return (self.A + self.f1(tmp, combined)) & 0xFFFFFFFF

    def incrementData(self):
        self.encData[0] = mask32(self.encData[0] + self.A)
        self.encData[1] = mask32(self.encData[1] + self.B)
        self.encData[2] = mask32(self.encData[2] + self.C)
        self.encData[3] = mask32(self.encData[3] + self.D)

    def result(self):
        return [mask32(x) for x in self.encData]


class Tag6FF1Encoder(Tag595BEncoder):
    md5table = md5magic2
    counter1 = 23

    def makeEncode(self):
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


class TagBF97Encoder(Tag6FF1Encoder):
    counter1 = 31


class TagE7A8Encoder(Tag595BEncoder):
    md5table = md5magic2
    loopParams = [17, 13, 12, 8]
    encodeParams = [
        0x50501010, 0xA010908, 0xA08097, 0x60606161,
        0x60606161, 0xA0008, 0x100097, 0x50501010,
    ]

    def initialData(self):
        return [0, 0, 0, 0]

    def makeEncode(self):
        ep = self.encodeParams
        lp = self.loopParams
        for p in range(lp[0]):
            self.A |= ep[0]
            self.B ^= ep[1]
            self.C |= (ep[2] - p) & 0xFFFFFFFF
            self.D ^= (ep[3] + p) & 0xFFFFFFFF
            for j in range(0, lp[2], 4):
                self.shortcut(self.f2, j, j + 32, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f3, j, j, 1, [1, -2, -1, 0])
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f5, j, j + 48, 3, [2, 3, 2, -3])
            self.incrementData()
        for p in range(lp[1]):
            self.A |= ep[4]
            self.B ^= ep[5]
            self.C |= (ep[6] - p) & 0xFFFFFFFF
            self.D ^= (ep[7] + p) & 0xFFFFFFFF
            for j in range(lp[3], 3, -4):
                self.shortcut(self.f4, j, j + 16, 2, [-3, -4, -1, 2])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f5, j, j + 32, 3, [2, 3, 2, -3])
            for j in range(lp[3], 0, -4):
                self.shortcut(self.f2, j, j, 0, [0, 1, 2, 3])
            for j in range(0, lp[2], 4):
                self.shortcut(self.f3, j, j + 48, 1, [1, -2, 3, 0])
            self.incrementData()

    def shortcut(self, fun, j, md5_index, rot_index, indexes):
        for i in range(4):
            t = self.calculate(fun, (j + indexes[i]) & 7, md5_index + i)
            self.A, self.D, self.C = self.D, self.C, self.B
            shift = rotationTable[rot_index][i]
            self.B = (self.B + rol(t, shift)) & 0xFFFFFFFF


class TagE7A8EncoderSecond(TagE7A8Encoder):
    def __init__(self, encBlock):
        super().__init__(encBlock)
        overfillArr = [
            (0xa0008 ^ 0x6d2f93a5),
            (0xa08097 ^ 0x6d2f93a5),
            (0xa010908 ^ 0x6d2f93a5),
            (0x60606161 ^ 0x6d2f93a5),
        ]
        self.md5table = md5magic2[:] + overfillArr
        self.loopParams = [17, 13, 12, 16]


def intArrayToByte(arr):
    out = []
    for num in arr:
        out.append(num & 0xFF)
        out.append((num >> 8) & 0xFF)
        out.append((num >> 16) & 0xFF)
        out.append((num >> 24) & 0xFF)
    return out


def byteArrayToInt(arr):
    out = []
    for i in range((len(arr) + 3) // 4):
        val = 0
        for k in range(4):
            if i * 4 + k < len(arr):
                val |= arr[i * 4 + k] << (8 * k)
        out.append(val & 0xFFFFFFFF)
    return out


# ------------------------------------------------- firmware-faithful suffix calc
# pw module 0x7d84 (calculateSuffix), type=1 call from the CF1B fallback 0x92b9:
#   arr = [tag[4], tag[3], tag[2], tag[1], tag[0]]  (copies at buf+8..buf+0xc)
#   suffix[i] via bit-shuffle, then r = 0xAA ^ (selected arr bytes by bits 0..4)
#   suffix[i] = T72[r % 72]      <-- firmware maps %72 (public tool used %len)
def calculateSuffix_fw(tag, table=T72, mod=72, arr=None):
    """pw module 0x7d84 (calculateSuffix).

    type=1 call (CF1B fallback 0x92b9): arr = [tag[4], tag[3], tag[2], tag[1], tag[0]]
    type=0 call (legacy fnA path):      arr = [fullSerial[8], fullSerial[9],
                                              fullSerial[10], fullSerial[1], fullSerial[0]]
    """
    if arr is None:  # type=1: tag bytes
        b = [ord(c) for c in tag]
        arr = [b[4], b[3], b[2], b[1], b[0]]
    suffix = [0] * 8
    suffix[0] = arr[0] & 0x1F
    suffix[1] = ((rol8(arr[1], 3) & 0xF1) | (arr[0] >> 5)) & 0x1F
    suffix[2] = (arr[1] >> 2) & 0x1F
    suffix[3] = (((arr[2] & 0xF) << 1) | (arr[1] >> 7)) & 0xFF
    suffix[4] = (((arr[3] & 1) << 4) | (arr[2] >> 4)) & 0xFF
    suffix[5] = (arr[3] >> 1) & 0x1F
    suffix[6] = (((arr[4] & 7) << 2) | (arr[3] >> 6)) & 0xFF
    suffix[7] = (arr[4] >> 3) & 0xFF
    out = []
    for i in range(8):
        r = 0xAA
        if suffix[i] & 1:
            r ^= arr[0]
        if suffix[i] & 2:
            r ^= arr[1]
        if suffix[i] & 4:
            r ^= arr[2]
        if suffix[i] & 8:
            r ^= arr[3]
        if suffix[i] & 16:
            r ^= arr[4]
        out.append(table[(r & 0xFF) % mod])
    return ''.join(out)


def md5_pad_block(msg23):
    """MD5-style padding of a 23-byte message into a 16-u32 block
    (firmware 0x7b94/0x7c90; identical to public keygenDell's encBlock)."""
    block = list(msg23) + [0] * (23 - len(msg23)) if len(msg23) < 23 else list(msg23[:23])
    block += [0] * (24 - len(block))      # 24 bytes
    block[23] = 0x80
    block += [0] * (64 - 24)              # to 64 bytes
    encBlock = byteArrayToInt(block)
    encBlock[14] = (23 << 3)              # bit count 184
    return encBlock


def keygen_cf1b(tag, suffix="CF1B", verbose=True):
    """Firmware CF1B path: fnB fallback (0x92b9) with out_len=16, flag=1.

    == keygenDell(tag, "BF97") semantics (validated against the public
    chromebreakerdev/DellBIOSTools implementation — byte-identical encode).
    """
    tag = tag.upper()
    # sanity: non-printable -> '*' (0x9418)
    tag = ''.join(c if 0x20 < ord(c) <= 0x7e else '*' for c in tag)
    sfx = calculateSuffix_fw(tag, T72, 72)
    data = (tag + "BF97" + sfx).encode('latin-1')   # 19 bytes
    encBlock = md5_pad_block(data)
    enc = TagBF97Encoder.encode(encBlock)           # 4 x u32
    enc16 = intArrayToByte(enc)                     # 16 bytes
    pw = ''.join(T72[b % 72] for b in enc16)
    if verbose:
        print(f"  [CF1B fw path] tag={tag} suffix-hash={sfx} block={data.decode('latin-1')!r}")
    return pw


class Tag595BEncoderWithSortedTable(Tag595BEncoder):
    md5table = md5magic2


def keygen_cf1b_alt_fnA(tag):
    """Alternate: fnA (0x904c) legacy path for unknown family (default 2A7B).

    fullSerial = tag+"2A7B"; type-0 suffix arr = [fs[8], fs[9], fs[10], fs[1], fs[0]];
    asciiPrintable table %72; encode via 0x7a0c 2A7B branch = simple 595B schedule
    over the SORTED table (md5magic2) with the 595B F-set; 16-char output.
    """
    tag = tag.upper()
    fs = tag + "2A7B"
    arr = [ord(fs[8]), ord(fs[9]), ord(fs[10]), ord(fs[1]), ord(fs[0])]
    ascii72 = ("012345679abcdefghijklmnopqrstuvwxyz0123456789"
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0")[:72]
    sfx = calculateSuffix_fw(tag, ascii72, 72, arr=arr)
    data = (fs + sfx).encode('latin-1')
    encBlock = md5_pad_block(data)
    enc = Tag595BEncoderWithSortedTable.encode(encBlock)
    enc16 = intArrayToByte(enc)
    return ''.join(ascii72[b % 72] for b in enc16)


def keygen_e7a8(serial):
    """Public/validated E7A8 derivation (also firmware 0x8ef4 path) - reference."""
    fullSerial = serial.upper() + "E7A8"
    arr = [ord(c) for c in fullSerial]
    encBlock = byteArrayToInt(arr)
    while len(encBlock) < 16:
        encBlock.append(0)
    out = []
    for klass in (TagE7A8Encoder, TagE7A8EncoderSecond):
        encoded = klass.encode(encBlock)
        res = intArrayToByte(encoded)
        digest = hashlib.sha256(bytes(res)).digest()
        out.append(''.join(E7A8_TABLE[(digest[i + 16] + digest[i]) % len(E7A8_TABLE)]
                           for i in range(16)))
    return out



# ----------------------------------------------------------------------------
# FULL LEGACY KEYGEN (all public families) — REPORT §14 / DELL_TOOLS_SURVEY
# keygen_dell_legacy(serial, tag) implements the public keygenDell() of
# bacher09/pwgen-for-bios (= bios-pw.org), which is the continuation of
# dogbert's bios-pwgen. All families with published test vectors:
#   595B D35B A95B 2A7B 1D3B 1F66 1F5A 6FF1 BF97 E7A8
# (3A5B exists only in dogbert's dell.c as a distinct blockEncode3A5B, with
#  no published vectors in either tool — not implemented here.)
# Validated against pwgen-for-bios' own dell.spec.ts vectors: 18/18 (§14).
# ----------------------------------------------------------------------------
SCAN_CODES = (chr(0) + chr(27) + "1234567890-=" + chr(8) + chr(9) +
              "qwertyuiop[]" + chr(13) + chr(255) + "asdfghjkl;'`" +
              chr(255) + chr(92) + "zxcvbnm,./")
ENCSCANS = [0x05, 0x10, 0x13, 0x09, 0x32, 0x03, 0x25, 0x11, 0x1F, 0x17,
            0x06, 0x15, 0x30, 0x19, 0x26, 0x22, 0x0A, 0x02, 0x2C, 0x2F,
            0x16, 0x14, 0x07, 0x18, 0x24, 0x23, 0x31, 0x20, 0x1E, 0x08,
            0x2D, 0x21, 0x04, 0x0B, 0x12, 0x2E]

EXTRA_CHARACTERS = {          # public extraCharacters map == TABLE_BANK
    "2A7B": TABLE_BANK["2A7B"][0],
    "1F5A": TABLE_BANK["1F5A"][0],
    "1D3B": TABLE_BANK["1D3B"][0],
    "1F66": TABLE_BANK["1F66"][0],
    "6FF1": TABLE_BANK["6FF1"][0],
    "BF97": TABLE_BANK["BF97"][0],
}


class TagD35BEncoder(Tag595BEncoder):
    f1 = staticmethod(encF1)
    f2 = staticmethod(encF2)
    f3 = staticmethod(encF3)
    f4 = staticmethod(encF4)
    f5 = staticmethod(encF5)


class Tag1D3BEncoder(Tag595BEncoder):
    def makeEncode(self):
        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= mask32(0x60606161 - j)
            self.D ^= mask32(0x50501010 + j)
            Tag595BEncoder.makeEncode(self)


class Tag1F66Encoder(Tag595BEncoder):
    md5table = md5magic2

    def makeEncode(self):
        for j in range(17):
            self.A |= 0x100097
            self.B ^= 0xA0008
            self.C |= mask32(0x60606161 - j)
            self.D ^= mask32(0x50501010 + j)
            for i in range(64):
                w = i >> 4
                if w == 0:
                    t = self.calculate(self.f2, i & 15, mask32(i + 16))
                elif w == 1:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15,
                                       mask32(i + 32))
                elif w == 2:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15,
                                       mask32(i - 2 * (i & 12) + 12))
                else:
                    t = self.calculate(self.f5, (i * 7) & 15,
                                       mask32(2 * (i & 3) - (i & 15) + 12))
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = mask32(self.B + rol(t, rotationTable[w][i & 3]))
            self.incrementData()
        for j in range(21):
            self.A |= 0x97
            self.B ^= 0x8
            self.C |= mask32(0x50501010 - j)
            self.D ^= mask32(0x60606161 + j)
            for i in range(64):
                w = i >> 4
                if w == 0:
                    t = self.calculate(self.f4, (i * 3 + 5) & 15,
                                       mask32(2 * (i & 3) - i + 44))
                elif w == 1:
                    t = self.calculate(self.f5, (i * 7) & 15,
                                       mask32(2 * (i & 3) - i + 76))
                elif w == 2:
                    t = self.calculate(self.f2, i & 15, i & 15)
                else:
                    t = self.calculate(self.f3, (i * 5 + 1) & 15,
                                       mask32(i - 32))
                g = w + 2
                self.A, self.D, self.C = self.D, self.C, self.B
                self.B = mask32(self.B + rol(t, rotationTable[g & 3][i & 3]))
            self.incrementData()


class Tag1F5AEncoder(Tag595BEncoder):
    md5table = md5magic2

    def makeEncode(self):
        for _ in range(5):
            for j in range(64):
                w = j >> 4
                k = 12 + (j & 3) - (j & 12)
                if w == 0:
                    t = self.calculate(self.f2, j & 15, j)
                elif w == 1:
                    t = self.calculate(self.f3, (j * 5 + 1) & 15, j)
                elif w == 2:
                    t = self.calculate(self.f4, (j * 3 + 5) & 15,
                                       mask32(k + 0x20))
                else:
                    t = self.calculate(self.f5, (j * 7) & 15,
                                       mask32(k + 0x30))
                # register order: B=D, D=A, A=C, C=rol(t)+C
                self.B, self.D, self.A, self.C = (self.D, self.A, self.C,
                                                  mask32(self.C + rol(
                                                      t, rotationTable[w][j & 3])))
            self.incrementData()

    def incrementData(self):
        # swapped accumulation vs 595B
        self.encData[0] = mask32(self.encData[0] + self.B)
        self.encData[1] = mask32(self.encData[1] + self.C)
        self.encData[2] = mask32(self.encData[2] + self.A)
        self.encData[3] = mask32(self.encData[3] + self.D)

    def calculate(self, func, key1, key2):
        tmp = func(self.C, self.A, self.D)
        combined = (self.md5table[key2 % len(self.md5table)] +
                    self.encBlock[key1]) & 0xFFFFFFFF
        return (self.B + self.f1(tmp, combined)) & 0xFFFFFFFF


LEGACY_ENCODERS = {
    "595B": Tag595BEncoder, "2A7B": Tag595BEncoder, "A95B": Tag595BEncoder,
    "1D3B": Tag1D3BEncoder, "D35B": TagD35BEncoder, "1F66": Tag1F66Encoder,
    "6FF1": Tag6FF1Encoder, "1F5A": Tag1F5AEncoder, "BF97": TagBF97Encoder,
}


def _legacy_pad(arr):
    """keygenDell block pad: ints -> 24 bytes ([23]=0x80) -> 16 LE u32,
    encBlock[14] = bitcount 184, [15] = 0."""
    a = list(arr)
    cnt = 23
    while len(a) <= cnt:
        a.append(0)
    a[cnt] = 0x80
    enc = []
    for i in range(len(a) // 4):
        enc.append(a[i * 4] | (a[i * 4 + 1] << 8) | (a[i * 4 + 2] << 16) |
                   (a[i * 4 + 3] << 24))
    while len(enc) < 16:
        enc.append(0)
    enc[14] = cnt << 3
    enc[15] = 0
    return enc


def _result_to_string(arr16, tag):
    """public resultToString: chartable families map every byte; 595B/D35B/
    A95B map via scanCodes from start index arr[0]%9 (max 8 chars)."""
    r = arr16[0] % 9
    out = ""
    table = EXTRA_CHARACTERS.get(tag)
    for i in range(16):
        if table is not None:
            out += table[arr16[i] % len(table)]
        elif r <= i and len(out) < 8:
            out += SCAN_CODES[ENCSCANS[arr16[i] % len(ENCSCANS)]]
    return out


def keygen_dell_legacy(serial, tag):
    """keygenDell(serial, tag, ServiceTag) — the public legacy construction,
    now for ALL families with published vectors. Returns list of passwords
    (E7A8 returns two). Validated 18/18 against pwgen-for-bios dell.spec.ts."""
    tag = tag.upper()
    serial = serial.upper()
    if tag == "E7A8":
        return keygen_e7a8(serial)
    if tag not in LEGACY_ENCODERS:
        raise ValueError(f"unsupported legacy tag {tag!r} "
                         "(3A5B: dogbert-only, no published vectors)")
    full = serial + ("595B" if tag == "A95B" else tag)
    full_arr = [ord(c) for c in full]
    if tag in EXTRA_CHARACTERS:      # chartable families: table[r % 72]
        sfx = [ord(c) for c in calculateSuffix_fw(
            full, EXTRA_CHARACTERS[tag], 72)]
    else:                            # 595B/D35B/A95B: encscans[r % 36]
        enc_tab = [chr(x) for x in ENCSCANS]
        sfx = [ord(c) for c in calculateSuffix_fw(full, enc_tab, 36)]
    enc_block = _legacy_pad(full_arr + sfx)
    enc16 = intArrayToByte(LEGACY_ENCODERS[tag].encode(enc_block))
    pw = _result_to_string(enc16, tag)
    return [pw] if pw else []

def selftest():
    """Cross-validate our E7A8 implementation against the public algorithm."""
    print("E7A8 self-test (known-good serials):")
    for serial in ("1A2B3C4", "7QJ4H42", "H2FS5S3"):
        pws = keygen_e7a8(serial)
        print(f"  {serial}: primary={pws[0]}  second={pws[1]}")
    print("  (compare against DellBiosTools 'Password Generator' E7A8 output)")

    # --- seven-table bank (REPORT §13.12) ---
    print("Seven-table bank self-test:")
    assert all(len(t) == 72 for t, _rva in TABLE_BANK.values())
    assert table_for("BF97") == T72
    assert table_for("E7A8") == E7A8_TABLE
    assert table_for("8FC8") == ALPHA_8FC8
    assert sorted(TABLE_BANK["8FC8"][0]) == sorted(TABLE_BANK["BF97"][0]), \
        "8FC8 table must be a permutation of the BF97 multiset"
    import os
    mod = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "optiplex3090", "pwmods",
                       "optiplex3090_2.0.7_pw_42k.efi")
    if os.path.isfile(mod):
        import pefile
        img = bytes(pefile.PE(data=open(mod, "rb").read(),
                              fast_load=True).get_memory_mapped_image())
        for fam, (t, rva) in TABLE_BANK.items():
            assert img[rva:rva + 72] == t.encode("latin1"), \
                f"{fam} table mismatch at RVA {rva:#x}"
        print(f"  all 7 tables byte-verified against pw_42k module "
              f"({os.path.basename(mod)})")
    else:
        print("  (module file not present — skipped byte-verification)")
    print("  bank checks passed")

    # --- full legacy keygen vs public vectors (pwgen-for-bios dell.spec.ts) ---
    print("Legacy keygen vs public test vectors (18):")
    vectors = [
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
    ]
    ok = 0
    for serial, tag, expected in vectors:
        got = keygen_dell_legacy(serial, tag)
        m = got and got[0] == expected
        ok += bool(m)
        if not m:
            print(f"  MISMATCH {serial}-{tag}: expected {expected!r} got {got!r}")
    print(f"  {ok}/{len(vectors)} public vectors reproduced"
          + (" — ALL PASS" if ok == len(vectors) else " <<< FAILURES"))


# 8FC8 output alphabet (72 chars, dispatch-table entry +0x10 for family 0x8FC8,
# .data RVA 0xA280 in the 42k pw module) — currently unused by the module's
# stubbed descriptor path, but the EC-side 8FC8 generator likely maps through it.
ALPHA_8FC8 = ("0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r")


def interpret_8fc8_response(hexstr):
    """Interpret the 32-byte cmd-0x21 mailbox response (see dell_8fc8_probe.c).

    The pw module compares response[0:16] against a stored config value and
    discards the response. If the response is input-independent (an oracle),
    its first 16 bytes ARE the machine's expected 8FC8 value. Depending on how
    the EC renders it, try: direct ASCII, or mapped through the candidate
    alphabets (b % 72).
    """
    hexstr = hexstr.replace(" ", "").replace(":", "")
    if len(hexstr) % 2:
        hexstr += "0"
    b = bytes.fromhex(hexstr)[:32]
    print(f"response ({len(b)} bytes): {b.hex()}")
    head = b[:16]
    if all(0x20 <= c < 0x7f for c in head):
        print("  [direct-ascii]   ", head.decode())
    for name, table in (("8FC8-alphabet", ALPHA_8FC8),
                        ("T72/BF97", T72),
                        ("E7A8", E7A8_TABLE)):
        pw = ''.join(table[c % 72] for c in head)
        print(f"  [{name:14s}]   {pw}")
    if len(b) == 32:
        tail = b[16:]
        print(f"  tail[16:32]:      {tail.hex()}")
        if all(0x20 <= c < 0x7f for c in tail):
            print("  [tail-ascii]     ", tail.decode())


SALT_227 = bytes.fromhex("8dfc7b25")   # EC-path salt, 2.27.0 pw_43k @0xA658 AND
                                      # 2.0.7 pw_42k @0xA648 — same value both
                                      # generations (REPORT §13.5); covers 8FC8
                                      # (2.0.7) and CF1B (2.27.0).
SALT_207 = b"0001"                    # pw_23k only (legacy/local module — NOT
                                      # the EC path; kept for reference).


def challenge_hash(data: bytes, salt: bytes = SALT_227) -> bytes:
    """SHA256(data || salt) — the 2.27.0/2.0.7 challenge primitive (fn 0x1bb4)."""
    import hashlib
    return hashlib.sha256(data + salt).digest()


def cmd_challenge(args):
    """--challenge <password> [salt-hex] : compute X and the expected EC response R."""
    pw = args[1].encode("latin-1")
    salt = bytes.fromhex(args[2]) if len(args) > 2 else SALT_227
    pw16 = pw[:16].ljust(16, b"\x00")          # type 3: exactly 16 bytes
    x = challenge_hash(pw16, salt)
    r = challenge_hash(x, salt)
    print(f"salt      : {salt.hex()}  ({salt!r})")
    print(f"candidate : {pw16.hex()}  (type 3, 16 B zero-padded)")
    print(f"X         : {x.hex()}   <- send this via dell_cf1b_probe --x")
    print(f"expected R: {r.hex()}   <- probe PASS iff R == this")


def cmd_findxenrolled(args):
    """--findxenrolled <flash/nvram-dump.bin> [more dumps...]

    Locate X_enrolled = SHA256(P_true || salt) in a raw SPI/BIOS dump.
    The enrolled hash lives in Dell's NVRAM record store (REPORT §13.7):
    records tagged by GUID 6e978d37-2ec3-43b6-8ceb-cc9aa215109e (record
    ids 0x10..0x1F), serialized in the flash NVRAM region. This tool scans
    for the GUID (both field orders) and lists plausible 32-byte hash
    records around it; feed candidates to --brute227.
    """
    if len(args) < 1:
        print(__doc__); return
    RECG = bytes.fromhex("378d976e2ec3b6438cebcc9aa215109e")   # as stored (mixed-endian)
    RECG_R = bytes.fromhex("6e978d37c32e43b68cebcc9aa215109e")  # swapped first 3 fields
    STORE = bytes.fromhex("d177a7b7b66e9e46ad1f1165eb92b3ff")
    for path in args:
        try:
            d = open(path, "rb").read()
        except OSError as e:
            print(f"{path}: {e}"); continue
        print(f"=== {path} ({len(d)} bytes) ===")
        marks = {}
        for name, pat in (("record-GUID", RECG), ("record-GUID(swapped)", RECG_R),
                          ("store-protocol-GUID", STORE)):
            i = d.find(pat)
            while i >= 0:
                marks.setdefault(i, []).append(name)
                i = d.find(pat, i + 1)
        if not marks:
            print("  no record/store GUID markers found (dump the full SPI, incl. NVRAM region)")
            continue
        for off in sorted(marks):
            print(f"  @{off:#x}: {', '.join(marks[off])}")
            for delta in (0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x30, 0x34):
                cand = d[off+delta:off+delta+32]
                if len(cand) < 32:
                    continue
                if cand.count(0) > 24 or cand.count(0xFF) > 24:
                    continue
                print(f"    +{delta:#04x}: {cand.hex()}")
        print("  -> try each candidate: python3 dell_keygen.py --brute227 <hash-hex>")


def cmd_brute227(args):
    """--brute227 <X_enrolled-hex> [charset] [minlen] [maxlen] [salt-hex]

    Offline recovery: find P with SHA256(P16 || salt) == X_enrolled.
    X_enrolled comes from the machine's NVRAM/SPI dump (per-machine data).
    """
    import hashlib
    import itertools
    if len(args) < 1:
        print(__doc__); return
    target = bytes.fromhex(args[0])
    charset = args[1] if len(args) > 1 else "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    lo = int(args[2]) if len(args) > 2 else 4
    hi = int(args[3]) if len(args) > 3 else 8
    salt = bytes.fromhex(args[4]) if len(args) > 4 else SALT_227
    print(f"target X_enrolled: {target.hex()}")
    print(f"charset: {charset!r}  len {lo}..{hi}  salt {salt.hex()}")
    tried = 0
    for n in range(lo, hi + 1):
        for tup in itertools.product(charset.encode(), repeat=n):
            pw = bytes(tup)
            if hashlib.sha256(pw.ljust(16, b"\x00") + salt).digest() == target:
                print(f"FOUND after {tried} tries: password = {pw.decode()!r}")
                return
            tried += 1
    print(f"not found ({tried} tries)")


def main():
    args = sys.argv[1:]
    if not args or args[0] == '--selftest':
        selftest()
        return
    if args[0] == '--interpret8fc8':
        interpret_8fc8_response(args[1] if len(args) > 1 else "")
        return
    if args[0] == '--challenge':
        cmd_challenge(args)
        return
    if args[0] == '--brute227':
        cmd_brute227(args)
        return
    if args[0] == '--findxenrolled':
        cmd_findxenrolled(args)
        return
    tag = args[0].upper()
    suffix = args[1].upper() if len(args) > 1 else "CF1B"
    print(f"Service tag: {tag}   Suffix: -{suffix}")
    print()
    print("PRIMARY (firmware CF1B path — pw module fallback, 16 chars):")
    print("  password:", keygen_cf1b(tag, suffix))
    print()
    print("ALTERNATES (in case the machine's path differs):")
    print("  [fnA-2A7B-legacy] ", keygen_cf1b_alt_fnA(tag))
    # E7A8 (in case config family was 0xE7A8)
    for i, p in enumerate(keygen_e7a8(tag)):
        print(f"  [E7A8 #{i+1}]        {p}")


if __name__ == '__main__':
    main()
