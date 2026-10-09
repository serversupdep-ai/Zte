#!/usr/bin/env python3
"""dell_vault_kdf.py — §11.20.6 conditional-door test: is the SIVB vault key
derived from the machine's service tag?

Inputs: a full-chip dump with a SIVB vault + the machine's 7-char service tag
(recoverable from the CSME '/<TAG>/<PPID>/' OEM string, the SMBIOS template
'\\x81\\x07\\x00<TAG>' records, or the chassis sticker).

Matrix: key candidates from the tag x {AES-128/256 ECB/CBC/CTR, RC4,
ChaCha20, SHA-CTR XOR keystream} x {data from +0, +16 (first block as IV)}.
Scoring: printable-ASCII fraction, zero/FF density, repeated 16B blocks,
known-string hits.  Any structured hit = the vault is tag-derivable.

Usage:
  python3 dell_vault_kdf.py <dump.bin> --tag ABC1234 [--vault-off 0x...]
  python3 dell_vault_kdf.py --selftest     # structural checks on canned data
"""
import hashlib
import math
import struct
import sys
from collections import Counter

from Crypto.Cipher import AES, ARC4, ChaCha20

MAGIC = b"SIVB"
KNOWN_STRINGS = [b"Dell", b"DELL", b"SIVB", b"ADMIN", b"SYSTEM", b"Setup",
                 b"admin", b"Password", b"password", b"ecode", b"AA"]


def find_vault(d):
    i = d.find(MAGIC)
    while i >= 0:
        if i >= 4 and (i % 0x100) == 4:
            return i - 4
        i = d.find(MAGIC, i + 1)
    return -1


def vault_data(d, off, max_len=0x4000):
    """data payload after the {u32 hdr, 'SIVB'} prefix, up to the zero pad."""
    start = off + 8
    end = min(off + 8 + max_len, len(d))
    blob = d[start:end]
    nz = len(blob.rstrip(b"\x00"))
    return blob[:nz] if nz else blob


def key_candidates(tag: str, const: bytes = b"", mat1: bytes = b""):
    t = tag.encode()
    cands = []
    cands.append(("tag+0pad16", (t + b"\x00" * 16)[:16]))
    cands.append(("tag+0pad32", (t + b"\x00" * 32)[:32]))
    cands.append(("tag+spad16", (t + b" " * 16)[:16]))
    cands.append(("tag+spad32", (t + b" " * 32)[:32]))
    cands.append(("sha256(tag)[:16]", hashlib.sha256(t).digest()[:16]))
    cands.append(("sha256(tag)", hashlib.sha256(t).digest()))
    cands.append(("md5(tag)", hashlib.md5(t).digest()))
    cands.append(("sha1(tag)[:16]", hashlib.sha1(t).digest()[:16]))
    cands.append(("tag*3[:16]", (t * 3)[:16]))
    cands.append(("tag*5[:32]", (t * 5)[:32]))
    cands.append(("tag+tag[:16]", (t + t)[:16]))
    cands.append(("tagrev+0pad16", (t[::-1] + b"\x00" * 16)[:16]))
    cands.append(("tag.lower+0pad16", (t.lower() + b"\x00" * 16)[:16]))
    cands.append(("sha256(tag.lower())", hashlib.sha256(t.lower()).digest()))
    cands.append(("tag+00 00..crc", (t + struct.pack("<I", zlib_crc32(t)) + b"\x00" * 16)[:16]))
    if const or mat1:
        c16, m16 = const[:16], mat1[:16]
        c32, m32 = (const + b"\x00" * 32)[:32], (mat1 + b"\x00" * 32)[:32]
        def hm(k, m):
            import hmac
            return hmac.new(k, m, hashlib.sha256).digest()
        more = [
            ("tag+const16", (t + c16)[:16]),
            ("const16+tag", (c16 + t)[:16]),
            ("tag^const16", bytes(a ^ b for a, b in zip((t + b"\x00" * 16)[:16], c16))),
            ("tag+const32", ((t + c32)[:32])),
            ("sha256(tag|const)", hashlib.sha256(t + const).digest()),
            ("sha256(const|tag)", hashlib.sha256(const + t).digest()),
            ("sha256(tag|const)[:16]", hashlib.sha256(t + const).digest()[:16]),
            ("hmac(tag,const)[:16]", hm(t, const)[:16]),
            ("hmac(const,tag)[:16]", hm(const, t)[:16]),
            ("hmac(tag,const)", hm(t, const)),
            ("hmac(const,tag)", hm(const, t)),
            ("tag+mat1_16", (t + m16)[:16]),
            ("sha256(tag|mat1)", hashlib.sha256(t + mat1).digest()),
            ("sha256(mat1|tag)", hashlib.sha256(mat1 + t).digest()),
            ("hmac(mat1,tag)[:16]", hm(m16, t)[:16]),
            ("sha256(const)[:16]", hashlib.sha256(const).digest()[:16]),
            ("sha256(const)", hashlib.sha256(const).digest()),
            ("sha256(const|tag)[:16]", hashlib.sha256(const + t).digest()[:16]),
            ("const16", c16),
            ("const32", c32),
            ("mat1_16", m16),
            ("mat1_32", m32),
            ("md5(tag|const)", hashlib.md5(t + const).digest()),
            ("md5(const|tag)", hashlib.md5(const + t).digest()),
            ("md5(tag|const|mat1)", hashlib.md5(t + const + mat1).digest()),
        ]
        cands.extend(more)
    return cands


def zlib_crc32(b):
    import zlib
    return zlib.crc32(b) & 0xFFFFFFFF


def score(pt: bytes):
    if not pt:
        return -1.0, {}
    n = len(pt)
    printable = sum(1 for x in pt if 0x20 <= x < 0x7f)
    zeros = pt.count(0)
    ffs = pt.count(0xFF)
    blocks = Counter(pt[i:i + 16] for i in range(0, n - 16, 16))
    rep = sum(v - 1 for v in blocks.values() if v > 1)
    hits = [s for s in KNOWN_STRINGS if s in pt]
    c = Counter(pt)
    ent = -sum(v / n * math.log2(v / n) for v in c.values())
    sc = (printable / n * 2.0 + zeros / n + ffs / n * 0.5 + rep * 0.02
          + (1.5 if hits else 0) - (ent / 8.0))
    return sc, {"printable": round(printable / n, 3), "zeros": round(zeros / n, 3),
                "ff": round(ffs / n, 3), "rep16": rep, "hits": hits,
                "entropy": round(ent, 3)}


def try_all(data: bytes, tag: str, const: bytes = b'', mat1: bytes = b''):
    results = []
    for kname, key in key_candidates(tag, const, mat1):
        variants = []
        # data from +0
        variants.append(("d0", data))
        if len(data) > 32:
            variants.append(("iv=d[0:16]", data[16:]))
        for vname, blob in variants:
            if len(blob) < 32:
                continue
            tests = []
            try:
                if len(key) in (16, 24, 32):
                    tests.append(("AES-ECB", AES.new(key, AES.MODE_ECB).decrypt(blob[:512])))
                    tests.append(("AES-CBC0", AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(blob[:512])))
                    ctr = AES.new(key, AES.MODE_CTR, nonce=b"\x00" * 8)
                    tests.append(("AES-CTR0", bytes(a ^ b for a, b in zip(blob[:512], ctr.encrypt(b"\x00" * 512)))))
                tests.append(("RC4", ARC4.new(key if len(key) <= 32 else key[:32]).decrypt(blob[:512])))
                if len(key) == 32:
                    tests.append(("ChaCha20", ChaCha20.new(key=key, nonce=b"\x00" * 12).decrypt(blob[:512])))
                if len(key) == 16:
                    ks = b"".join(hashlib.sha256(key + bytes([i])).digest() for i in range(16))
                    tests.append(("SHA-CTR-XOR", bytes(a ^ b for a, b in zip(blob[:512], ks[:512]))))
            except Exception:
                continue
            for name, pt in tests:
                sc, det = score(pt)
                results.append((sc, f"{kname:22s} {vname:10s} {name:11s}", det, pt[:48]))
    results.sort(reverse=True, key=lambda r: r[0])
    return results


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        print("selftest: structural scoring sanity")
        sc1, _ = score(b"Dell" * 100)
        sc2, _ = score(bytes(range(256)) * 2)
        assert sc1 > sc2, "scoring sanity failed"
        print(f"  ascii={sc1:.2f} > random={sc2:.2f}  OK")
        return
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    tag = None
    voff = None
    for a in sys.argv[2:]:
        if a.startswith("--tag="):
            tag = a.split("=", 1)[1]
        elif a == "--tag" and sys.argv.index(a) + 1 < len(sys.argv):
            tag = sys.argv[sys.argv.index(a) + 1]
        elif a.startswith("--vault-off="):
            voff = int(a.split("=", 1)[1], 0)
    d = open(path, "rb").read()
    if voff is None:
        voff = find_vault(d)
        if voff < 0:
            sys.exit("no SIVB vault found")
    data = vault_data(d, voff)
    print(f"dump      : {path}")
    print(f"vault     : @ {voff:#x}  hdr={struct.unpack_from('<I', d, voff)[0]:#010x}")
    print(f"data len  : {len(data)}")
    print(f"tag       : {tag}")
    print(f"ciphertext[0:32]: {data[:32].hex()}")
    print()
    const = b""
    mat1 = b""
    for a in sys.argv[2:]:
        if a.startswith("--const="):
            const = bytes.fromhex(a.split("=", 1)[1])
        elif a.startswith("--mat1="):
            mat1 = bytes.fromhex(a.split("=", 1)[1])
    res = try_all(data, tag, const, mat1)
    print("top 15 candidates by structure score:")
    for sc, name, det, head in res[:15]:
        print(f"  {sc:6.2f}  {name}  {det}  head={head.hex()}")
    # cross-check: decrypt with a WRONG tag must score lower
    wrong = bytearray(tag.encode())
    wrong[0] = ord('A') if tag[0] != 'A' else ord('B')
    wres = try_all(data, wrong.decode(), const, mat1)
    print()
    print(f"wrong-tag top score: {wres[0][0]:.2f} vs right-tag top: {res[0][0]:.2f}"
          if wres else "no wrong-tag results")


if __name__ == "__main__":
    main()
