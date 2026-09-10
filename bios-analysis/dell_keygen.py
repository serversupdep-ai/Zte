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


def selftest():
    """Cross-validate our E7A8 implementation against the public algorithm."""
    print("E7A8 self-test (known-good serials):")
    for serial in ("1A2B3C4", "7QJ4H42", "H2FS5S3"):
        pws = keygen_e7a8(serial)
        print(f"  {serial}: primary={pws[0]}  second={pws[1]}")
    print("  (compare against DellBiosTools 'Password Generator' E7A8 output)")


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


def main():
    args = sys.argv[1:]
    if not args or args[0] == '--selftest':
        selftest()
        return
    if args[0] == '--interpret8fc8':
        interpret_8fc8_response(args[1] if len(args) > 1 else "")
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
