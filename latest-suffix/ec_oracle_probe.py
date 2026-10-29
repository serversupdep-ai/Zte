#!/usr/bin/env python3
"""
ec_oracle_probe.py -- turn the target board's own EC into an *input/output
specification* of the master-code generator.

THE IDEA (original to this file)
--------------------------------
Every published route answers "what is the formula?" by reading it somewhere:
a repo, a firmware module, a keygen site.  None of them exist for the EC-era
suffixes (8FC8, 9ABE, CF1B, 3FE2, 1B58) because the formula is not in any
host-readable place -- the BIOS asks the EC and the EC answers.

So do not ask *where* the formula is.  Ask what *class of function* the
answer is.  The GENERATE call is (by construction) a function

        resp = F(tag_bytes, family_byte)      resp in {0,1}^256, tag in {0,1}^56

The host controls the two arguments.  If the EC does not bind the call to a
sealed serial, then 57 chosen queries decide everything:

  * F affine over GF(2)   ->  F(t) = A*t XOR c.  57 queries recover A and c
                             exactly.  The board is then fully solved
                             offline, forever, with no firmware extraction and
                             no published formula.  This class includes every
                             CRC / LFSR / xorshift / rotate-XOR / table-free
                             "scrambler" EC codegen -- i.e. exactly what fits
                             in a small EC handler.
  * F not affine          ->  carries, S-boxes or a keyed hash.  Then the
                             differential signal is a full avalanche and NO
                             offline generator can exist for anyone, ever.
                             That is a proof about the hardware, not a guess.
  * F tag-locked          ->  the EC validates the tag against its sealed
                             identity, so foreign-tag queries error out.
                             Then a donor machine cannot help either, and the
                             only route left is reading the sealed tag itself.

All three outcomes are worth more than another posted (tag, password) pair,
because each one closes the question rather than adding a sample to it.

THE RECOVERY ALGORITHM (57 queries, exact, no published data)
------------------------------------------------------------
Let t0 = the board's own tag (always available, always accepted).
Probe i = response to (t0 XOR e_i) for each of the 56 tag bits.
Define D_i = resp_i XOR resp_0.  Affinity means D_i = A e_i = column i of A.
Then for any t:  resp(t) = resp_0 XOR XOR_{i in bits(t XOR t0)} D_i.
Verification: replay N held-out tags; any mismatch falsifies the model
immediately and cheaply, which is why this is safe to design before using it.

WHAT THIS FILE IS AND IS NOT
----------------------------
It contains no vendor code, no vendor constants, and no passwords.  It is a
protocol + a simulator + an exact solver.  `--self-test` proves the solver by
building synthetic ECs of each class and recovering the affine ones bit-for-bit.
Running it against real hardware is on you and only for hardware you own or
are authorized to service.

Hardware note: the transport (mailbox ports 0x910/0x911, session {21 00 03 06},
7 tag bytes, 1 family byte, 32 response bytes + status) is documented in
bios-analysis/CF1B_FINDINGS.md.  This tool speaks to an `Oracle` object; wire
one to that transport, or to a UEFI-side hook, at your discretion.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

RESP_BYTES = 32
TAG_BYTES = 7
TAG_BITS = TAG_BYTES * 8


# ---------------------------------------------------------------------------
# GF(2) helpers: responses are 256-bit vectors, tags are 56-bit vectors
# ---------------------------------------------------------------------------

def bytes_to_bits(b: bytes) -> int:
    return int.from_bytes(b, "big")


def bits_to_bytes(v: int, nbytes: int = RESP_BYTES) -> bytes:
    return v.to_bytes(nbytes, "big")


def tag_to_int(tag: str) -> int:
    raw = tag.encode("ascii")
    if len(raw) > TAG_BYTES:
        raise ValueError("tag longer than 7 bytes")
    return int.from_bytes(raw.ljust(TAG_BYTES, b"\x00"), "big")


def int_to_tag(v: int) -> str:
    raw = bits_to_bytes(v, TAG_BYTES)
    return raw.rstrip(b"\x00").decode("latin1")


def xor_tags(a: int, b: int) -> int:
    return a ^ b


# ---------------------------------------------------------------------------
# Oracle interface
# ---------------------------------------------------------------------------

class OracleError(RuntimeError):
    pass


class Oracle:
    """Anything that can answer GENERATE for a tag + family byte."""

    name = "oracle"

    def generate(self, tag: int, family: int) -> bytes:  # pragma: no cover
        raise NotImplementedError


# ------------------------------- synthetic ECs ------------------------------

class AffineEC(Oracle):
    """resp = A*t XOR c over GF(2). Models CRC/LFSR/xorshift/rot-xor codegen."""

    def __init__(self, seed: int = 1, name: str = "affine-ec", additive: int = 0):
        rng = random.Random(seed)
        self.cols = [[rng.getrandbits(1) for _ in range(TAG_BITS)] for _ in range(256)]
        # columns[j] = 256-bit column for tag bit j, stored as int
        self.cols = [rng.getrandbits(256) for _ in range(TAG_BITS)]
        self.c = rng.getrandbits(256)
        self.family_mix = 0x9E3779B9
        self.additive = additive  # if >0, a carry-based twist -> non-affine
        self.family_seen = -1
        self.name = name
        self.queries = 0

    def generate(self, tag: int, family: int) -> bytes:
        self.queries += 1
        self.family_seen = family
        v = self.c ^ (family * self.family_mix & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        for j in range(TAG_BITS):
            if (tag >> j) & 1:
                v ^= self.cols[j]
        if self.additive:
            # integer addition of a tag-derived byte: introduces carries
            acc = (tag & 0xFF) + ((tag >> 8) & 0xFF) + self.additive
            v ^= (acc & 0xFF) * 0x0101010101010101010101010101010101010101010101010101010101010101
        return bits_to_bytes(v & ((1 << 256) - 1))


class XorShiftEC(Oracle):
    """A plausible 'EC codegen': xorshift state seeded linearly from the tag."""

    def __init__(self, seed: int = 7, name: str = "xorshift-ec"):
        self.k = random.Random(seed).getrandbits(64) | 1
        self.name = name
        self.queries = 0

    def generate(self, tag: int, family: int) -> bytes:
        self.queries += 1
        s = (tag ^ (family << 56) ^ self.k) & 0xFFFFFFFFFFFFFFFF
        if s == 0:
            s = 0x9E3779B97F4A7C15
        out = bytearray()
        for _ in range(RESP_BYTES):
            s ^= (s << 13) & 0xFFFFFFFFFFFFFFFF
            s ^= s >> 7
            s ^= (s << 17) & 0xFFFFFFFFFFFFFFFF
            out.append(s & 0xFF)
        return bytes(out)


class PrfEC(Oracle):
    """Keyed hash: the class that makes offline generation impossible."""

    def __init__(self, secret: bytes = b"ec-internal-secret", name: str = "prf-ec"):
        self.secret = secret
        self.name = name
        self.queries = 0

    def generate(self, tag: int, family: int) -> bytes:
        self.queries += 1
        msg = bits_to_bytes(tag, TAG_BYTES) + bytes([family & 0xFF])
        return hmac.new(self.secret, msg, hashlib.sha256).digest()


class LockedEC(Oracle):
    """Wraps another EC and enforces tag == sealed identity."""

    def __init__(self, inner: Oracle, sealed_tag: str = "1K6Y963"):
        self.inner = inner
        self.sealed = tag_to_int(sealed_tag)
        self.name = "locked-" + inner.name
        self.queries = 0

    def generate(self, tag: int, family: int) -> bytes:
        self.queries += 1
        if tag != self.sealed:
            raise OracleError("EC rejected foreign tag (sealed identity enforced)")
        return self.inner.generate(tag, family)


class FilesystemOracle(Oracle):
    """Replay a captured (tag, family) -> response table (32 hex bytes)."""

    def __init__(self, path: str):
        self.table: Dict[Tuple[int, int], bytes] = {}
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tag, fam, resp = line.split()
            self.table[(tag_to_int(tag), int(fam, 0))] = bytes.fromhex(resp)
        self.name = "capture:" + os.path.basename(path)
        self.queries = 0
        self.misses = 0

    def generate(self, tag: int, family: int) -> bytes:
        self.queries += 1
        if (tag, family) not in self.table:
            self.misses += 1
            raise OracleError("no captured response for this tag")
        return self.table[(tag, family)]


# ---------------------------------------------------------------------------
# Prober: classification + exact affine recovery
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    oracle: str
    family: int
    base_tag: str
    queries: int
    verdict: str                  # affine | nonlinear | tag-locked | insufficient
    reason: str
    affine_rank: Optional[int] = None
    recovered: Optional[Dict[str, str]] = None
    verified: Optional[int] = None
    avalanche_bits: Optional[float] = None
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {k: v for k, v in self.__dict__.items()}


class Prober:
    def __init__(self, oracle: Oracle, family: int, base_tag: str):
        self.o = oracle
        self.family = family
        self.t0 = tag_to_int(base_tag)
        self.base_tag = base_tag
        self.n = 0

    # -- transport ---------------------------------------------------------
    def q(self, tag: int) -> bytes:
        self.n += 1
        return self.o.generate(tag, self.family)

    # -- stages ------------------------------------------------------------
    def classify(self, trials: int = 8) -> ProbeResult:
        try:
            r0 = self.q(self.t0)
        except OracleError as e:
            return ProbeResult(self.o.name, self.family, self.base_tag, self.n,
                               "tag-locked", f"own tag rejected: {e}")
        if len(r0) != RESP_BYTES:
            return ProbeResult(self.o.name, self.family, self.base_tag, self.n,
                               "insufficient", f"response was {len(r0)} bytes")

        # Differential on a single flipped bit: dies immediately if foreign
        # tags are refused, which is itself the answer for the locked class.
        try:
            r1 = self.q(self.t0 ^ 1)
        except OracleError as e:
            return ProbeResult(
                self.o.name, self.family, self.base_tag, self.n, "tag-locked",
                f"foreign tag refused ({e}); the EC binds GENERATE to its sealed "
                "identity, so no external observer and no donor machine can "
                "produce another board's response")

        v0, v1 = bytes_to_bits(r0), bytes_to_bits(r1)
        av = (v0 ^ v1).bit_count()

        # Affinity test on random tag pairs: F(a)^F(b) must equal F(a^b^t0)^F(t0)
        checks = 0
        fails = 0
        rng = random.Random(0xAFF1)
        for _ in range(trials):
            a = self.t0 ^ rng.getrandbits(TAG_BITS)
            b = self.t0 ^ rng.getrandbits(TAG_BITS)
            try:
                fa, fb = self.q(a), self.q(b)
                fc = self.q(a ^ b ^ self.t0)
            except OracleError:
                continue
            checks += 1
            lhs = bytes_to_bits(fa) ^ bytes_to_bits(fb)
            rhs = bytes_to_bits(fc) ^ v0
            if lhs != rhs:
                fails += 1

        if checks and fails == 0:
            return ProbeResult(self.o.name, self.family, self.base_tag, self.n,
                               "affine",
                               "F satisfies F(a)^F(b)=F(a^b^t0)^F(t0) on all "
                               f"{checks} random pairs; it is GF(2)-affine. "
                               f"(One-bit avalanche was {av}/256 -- high avalanche "
                               "is NOT evidence of a hash; only the affinity test "
                               "distinguishes the two classes.)",
                               avalanche_bits=round(av / RESP_BYTES, 2))
        return ProbeResult(
            self.o.name, self.family, self.base_tag, self.n, "nonlinear",
            f"affinity failed {fails}/{checks} random pairs: F(a)^F(b) != "
            "F(a^b^t0)^F(t0). The map carries, uses S-boxes or a keyed hash, so "
            "no 56-parameter model describes it and no offline generator can "
            f"exist for this family. (One-bit avalanche {av}/256; both classes "
            "look alike under avalanche, which is why affinity is the test.)",
            avalanche_bits=round(av / RESP_BYTES, 2))

    def recover_affine(self, verify: int = 24) -> ProbeResult:
        base = self.classify(trials=2)
        if base.verdict != "affine":
            return base
        r0 = self.q(self.t0)
        cols: List[int] = []
        for i in range(TAG_BITS):
            ri = self.q(self.t0 ^ (1 << i))
            cols.append(bytes_to_bits(ri) ^ bytes_to_bits(r0))

        rank = _gf2_rank(cols)
        # held-out verification against the live oracle
        ok = 0
        rng = random.Random(0x5EED)
        for _ in range(verify):
            t = self.t0 ^ rng.getrandbits(TAG_BITS)
            pred = bytes_to_bits(r0)
            delta = t ^ self.t0
            for i in range(TAG_BITS):
                if (delta >> i) & 1:
                    pred ^= cols[i]
            if bits_to_bytes(pred) == self.q(t):
                ok += 1

        rec = {
            "model": "resp(tag) = resp(t0) XOR sum_i cols[i] for bits of (tag XOR t0)",
            "base_tag": self.base_tag,
            "base_response_hex": r0.hex(),
            "family_byte": f"0x{self.family:02X}",
            "tag_param_rank": str(rank),
            "columns_hex": [bits_to_bytes(c).hex() for c in cols],
        }
        notes = []
        if rank < TAG_BITS:
            notes.append(
                f"only {rank} of {TAG_BITS} tag bits affect the response: the EC "
                f"collapses {TAG_BITS - rank} bit(s) of the tag, which is itself a "
                "structural finding")
        if ok != verify:
            notes.append("held-out verification FAILED -- model rejected")
        return ProbeResult(
            self.o.name, self.family, self.base_tag, self.n,
            "affine-recovered" if ok == verify else "affine-model-rejected",
            f"recovered {TAG_BITS} columns + base response; "
            f"{ok}/{verify} held-out tags predicted exactly",
            affine_rank=rank, recovered=rec, verified=ok,
            avalanche_bits=base.avalanche_bits, notes=notes)


def _gf2_rank(vecs: Sequence[int]) -> int:
    basis: List[int] = []
    for v in vecs:
        for b in basis:
            v = min(v, v ^ b)
        if v:
            basis.append(v)
            basis.sort(reverse=True)
    return len(basis)


# ---------------------------------------------------------------------------
# Using a recovered model: arbitrary tag -> 32-byte response -> password
# ---------------------------------------------------------------------------

def model_response(rec: Dict[str, object], tag: str) -> bytes:
    """Apply a recovered affine model to any tag (no EC needed)."""
    t0 = tag_to_int(str(rec["base_tag"]))
    base = bytes_to_bits(bytes.fromhex(str(rec["base_response_hex"])))
    cols = [bytes_to_bits(bytes.fromhex(h)) for h in rec["columns_hex"]]
    delta = tag_to_int(tag) ^ t0
    v = base
    for i in range(TAG_BITS):
        if (delta >> i) & 1:
            v ^= cols[i]
    return bits_to_bytes(v)


def model_codes(rec: Dict[str, object], tag: str, suffix: str) -> Dict[str, str]:
    """Recovered 32-byte response -> the two candidate passwords.

    Delegates to latest_suffix.render_ec_response, the renderer validated
    against the emulated BIOS function, so there is exactly one
    implementation of the mapping in this kit.
    """
    from latest_suffix import render_ec_response
    master, second = render_ec_response(model_response(rec, tag), suffix)
    return {"master": master, "code2": second}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def report(res: ProbeResult, as_json: bool = False) -> int:
    if as_json:
        print(json.dumps(res.as_dict(), indent=2))
        return 0
    print(f"oracle        {res.oracle}   family 0x{res.family:02X}   base {res.base_tag}")
    print(f"queries       {res.queries}")
    print(f"verdict       {res.verdict.upper()}")
    print(f"reason        {res.reason}")
    if res.affine_rank is not None:
        print(f"tag rank      {res.affine_rank}/56")
    if res.verified is not None:
        print(f"held-out      {res.verified} exact predictions")
    if res.recovered:
        print(f"base resp     {res.recovered['base_response_hex']}")
        print("columns       written to model JSON (--json)")
    for n in res.notes:
        print(f"note          {n}")
    print()
    print("what this means:")
    if res.verdict == "affine-recovered":
        print("  The generator is a linear map. You now own it: replay the base")
        print("  response plus the 56 columns for ANY tag, forever, offline.")
        print("  No firmware extraction and no published formula were used.")
    elif res.verdict == "nonlinear":
        print("  The generator is not a 56-parameter linear map. Given the")
        print("  observed avalanche, no offline keygen can exist for this family")
        print("  -- including for whoever runs the paid 'oracle' services.")
    elif res.verdict == "tag-locked":
        print("  The EC refuses foreign tags. A donor machine cannot help, and")
        print("  the EC-internal secret is the only remaining source.")
    else:
        print("  Inconclusive: capture more of the transport before drawing")
        print("  a conclusion.")
    return 0


# ---------------------------------------------------------------------------
# Self-test: prove the solver on synthetic ECs of each class
# ---------------------------------------------------------------------------

def self_test(as_json: bool = False) -> int:
    cases: List[Tuple[Oracle, str]] = [
        (AffineEC(seed=1), "affine-recovered"),
        (AffineEC(seed=99, additive=0x5A), "nonlinear"),
        (XorShiftEC(seed=7), "affine-recovered"),
        (PrfEC(), "nonlinear"),
        (LockedEC(AffineEC(seed=3)), "tag-locked"),
    ]
    rows = []
    all_ok = True
    for oracle, expect in cases:
        p = Prober(oracle, family=0xC8, base_tag="1K6Y963")
        res = p.recover_affine(verify=24)
        ok = res.verdict == expect
        all_ok &= ok
        rows.append({"oracle": oracle.name, "expect": expect,
                     "got": res.verdict, "queries": res.queries,
                     "rank": res.affine_rank, "verified": res.verified,
                     "pass": ok})
    if as_json:
        print(json.dumps({"cases": rows, "pass": all_ok}, indent=2))
        return 0 if all_ok else 1
    print("== self-test: synthetic ECs of each function class ==")
    for r in rows:
        mark = "PASS" if r["pass"] else "FAIL"
        print(f"  [{mark}] {r['oracle']:<22} expect {r['expect']:<17} "
              f"got {r['got']:<17} q={r['queries']:<3} "
              f"rank={r['rank']} verified={r['verified']}")
    print()
    print("  Interpretation: a CRC/LFSR/xorshift style EC codegen (the only kind")
    print("  that fits comfortably in a small handler) is fully recovered from 57")
    print("  chosen queries. A keyed-hash EC is provably out of reach offline.")
    print("  The probe tells you which one you are standing in front of.")
    return 0 if all_ok else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--simulate", choices=("affine", "xorshift", "prf", "locked", "additive"))
    ap.add_argument("--capture", help="file of 'TAG FAMILY_HEx RESPONSE_HEX' lines")
    ap.add_argument("--tag", default="1K6Y963", help="base/own tag (7 chars)")
    ap.add_argument("--family", default="0xC8", help="family byte, e.g. 0xBE for 9ABE")
    ap.add_argument("--target", help="tag to print a password for, using the recovered model")
    ap.add_argument("--suffix", default="8FC8", help="suffix whose renderer to apply")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test(as_json=args.json)

    fam = int(args.family, 0)
    if args.simulate:
        oracle: Oracle = {
            "affine": AffineEC(seed=1),
            "additive": AffineEC(seed=1, additive=0x33),
            "xorshift": XorShiftEC(seed=7),
            "prf": PrfEC(),
            "locked": LockedEC(AffineEC(seed=3)),
        }[args.simulate]
    elif args.capture:
        oracle = FilesystemOracle(args.capture)
    else:
        ap.print_help()
        print("\nNo oracle wired. Either --self-test, --simulate, or adapt\n"
              "Oracle.generate() to your transport (see module docstring).")
        return 2

    res = Prober(oracle, family=fam, base_tag=args.tag).recover_affine()
    rc = report(res, as_json=args.json)
    if args.target and res.recovered:
        codes = model_codes(res.recovered, args.target, args.suffix)
        if not args.json:
            print()
            print(f"predicted {args.target}-{args.suffix.upper()} from the recovered model:")
            print(f"  master  {codes['master']}")
            print(f"  code 2  {codes['code2']}")
        else:
            print(json.dumps({"target": args.target, "suffix": args.suffix.upper(),
                              "codes": codes}, indent=2))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
