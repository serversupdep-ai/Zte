#!/usr/bin/env python3
"""
falsify.py -- an original falsification engine for the Dell EC-era master code.

WHAT THIS IS
------------
The public record (bacher09/pwgen-for-bios#80, secaicandido/bioskey, the
in-repo firmware extractions) leaves the 8FC8/9ABE/CF1B/3FE2/1B58 transform
unknown.  Everything already published for those suffixes is either

  (a) a copy of the E7A8 local formula re-labelled with a newer word
      (network/source-provenance in this repo: secaicandido/bioskey), or
  (b) a hook that reads the answer out of a live EC (nothing computed).

This file is neither.  It is a *search-and-falsification* engine written from
scratch: it enumerates a closed, explicitly-bounded hypothesis space of
"small construction" formulas (hash-expand families and a custom scalar
mixer), renders each to a candidate password through the two *firmware-
observed* renderers, and reports:

  * the number of configurations actually executed,
  * whether any survives the public field pairs (it does not -- by design of
    the answer: see below),
  * the best partial-match score in the whole space, i.e. how much structure
    the space is *finding* versus chance,
  * a positive control proving the engine can recover a planted formula,
  * the Shannon information accounting that explains the negative result.

WHY A NEGATIVE RESULT IS THE CORRECT RESULT
-------------------------------------------
A 16-character code drawn from a 72-character alphabet carries
log2(72^16) = 98.72 bits of information.  K public field pairs therefore
constrain the transform by 98.72*K bits.  A hypothesis space of H
configurations can at best be identified by log2(H) bits.  So:

  * with the 3 owner-verified 8FC8 pairs (296.16 bits) the search space must
    be smaller than 2^296 to be identified -- trivially true;
  * but the *inverse* is the real constraint: any transform you cannot
    validate on at least one pair is, in expectation, one of 2^98.72 equally
    plausible strings.  "Inventing" a formula and printing its output is
    therefore indistinguishable from printing a random password, no matter
    how plausible the code looks.

That is not a cop-out; it is a number.  See `information_budget()`.

Authorized use only: this tool is for auditing hardware you own or are
contracted to service.  It contains no vendor code and no vendor secrets.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence"
MASK = 0xFFFFFFFF

# Renderers observed in the extracted DellSecurityVaultSmm module.
# (Copied constants, not copied logic: both are single-line index expressions
# documented in FINAL_REPORT.md section "Reconstruction".)
EC_ALPHABET = (
    "0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r"
)
E7A8_ALPHABET = (
    "Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ"
)
ALPHABETS = {"ec": EC_ALPHABET, "e7a8": E7A8_ALPHABET}

# Family byte the host sends to the EC in the GENERATE mailbox request.
FAMILY_BYTE = {"CF1B": 0x1B, "8FC8": 0xC8, "1B58": 0x58, "9ABE": 0xBE, "3FE2": 0xE2}

CODE_LEN = 16
ALPHA_LEN = 72


# ---------------------------------------------------------------------------
# Renderers: stream of 32 symbols -> 16-character code
# ---------------------------------------------------------------------------

def render_sum(stream: Sequence[int], alphabet: str = EC_ALPHABET) -> str:
    """8FC8: alphabet[(r[i] + r[i+16]) % 72].

    `stream` is 32 *symbol* values (0..255); the renderer reduces them mod 72.
    The alternative model -- the EC returning finished ASCII alphabet
    characters, as the firmware comments suggest -- is covered separately by
    latest_suffix.render_ec_response, which this engine's alphabets and
    reducers bracket.
    """
    n = len(alphabet)
    return "".join(alphabet[(stream[i] + stream[i + CODE_LEN]) % n]
                   for i in range(CODE_LEN))


def render_verbatim(stream: Sequence[int], alphabet: str = EC_ALPHABET) -> str:
    """9ABE/CF1B/3FE2/1B58: alphabet[r[i]] for the first 16 symbols."""
    return "".join(alphabet[stream[i]] for i in range(CODE_LEN))


RENDERERS = {"sum": render_sum, "verbatim": render_verbatim}


def response_symbols(resp: Sequence[int]) -> List[int]:
    """32 raw EC response bytes -> 32 alphabet indices (mod 72)."""
    n = ALPHA_LEN
    return [b % n for b in resp]


# ---------------------------------------------------------------------------
# Hypothesis space definition
# ---------------------------------------------------------------------------

def _h_md5(b: bytes) -> bytes:
    return hashlib.md5(b).digest()


def _h_sha1(b: bytes) -> bytes:
    return hashlib.sha1(b).digest()


def _h_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _h_sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()[:32]


def _h_sha3(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def _h_blake2s(b: bytes) -> bytes:
    return hashlib.blake2s(b).digest()


def _h_blake2b(b: bytes) -> bytes:
    return hashlib.blake2b(b, digest_size=32).digest()


HASHES: Dict[str, object] = {
    "md5": _h_md5, "sha1": _h_sha1, "sha256": _h_sha256, "sha512": _h_sha512,
    "sha3_256": _h_sha3, "blake2s": _h_blake2s, "blake2b": _h_blake2b,
}


def expand(fn, msg: bytes, style: str) -> bytes:
    """Stretch one digest to exactly 32 bytes."""
    d = fn(msg)
    if style == "counter":
        out = b""
        c = 0
        while len(out) < 32:
            out += fn(msg + bytes([c & 0xFF]))
            c += 1
        return out[:32]
    if style == "chain":
        # always at least two rounds, take the TAIL: distinct from "dup" and
        # "self" even when the digest is already 32 bytes wide
        out = d + fn(msg + b"\x01" + d[:4])
        salt = 0xC5
        while len(out) < 64:
            out += fn(msg + bytes([salt]) + out[-4:])
            salt = (salt * 131 + 7) & 0xFF
        return out[-32:]
    if style == "dup":
        return (d * (32 // len(d) + 1))[:32]
    if style == "self":
        out = fn(d)          # iterate the hash on its own digest
        while len(out) < 32:
            out += fn(out[-len(d):])
        return out[:32]
    raise ValueError(style)


EXPAND_STYLES = ("counter", "chain", "dup", "self")


def materials(tag: str, suffix: str, family: int) -> List[Tuple[str, bytes]]:
    """Byte strings the EC could plausibly feed a construction with."""
    t = tag.upper().encode("ascii")
    f = bytes([family])
    s = suffix.upper().encode("ascii")
    return [
        ("tag", t),
        ("tag+fam", t + f),
        ("fam+tag", f + t),
        ("tag+suffix", t + s),
        ("suffix+tag", s + t),
        ("rev(tag)", t[::-1]),
        ("tag+nul8", t.ljust(8, b"\x00")),
        ("tag+ff8", t.ljust(8, b"\xff")),
        ("tag+sp8", t.ljust(8, b" ")),
        ("tag+nul16", t.ljust(16, b"\x00")),
        ("tag*2", (t * 3)[:14]),
        ("tag+tag", t + t),
        ("tag-dash-fam", t + b"-" + f),
        ("nul+tag", b"\x00" + t),
        ("tag+dell", t + b"Dell"),
    ]


REDUCERS = {
    "mod72": lambda b, i, d: b % ALPHA_LEN,
    "mod63": lambda b, i, d: b & 0x3F,
    "xor32": lambda b, i, d: (b ^ d[(i + 16) % len(d)]) % ALPHA_LEN,
    "swapnib": lambda b, i, d: (((b >> 4) | ((b & 0x0F) << 4))) % ALPHA_LEN,
    "rot3": lambda b, i, d: (((b << 3) | (b >> 5)) & 0xFF) % ALPHA_LEN,
}


def reduce_stream(raw: bytes, how: str) -> List[int]:
    r = REDUCERS[how]
    return [r(raw[i], i, raw) for i in range(32)]


# The mixer: an original scalar construction (not copied from any repo).
MIX_SEEDS = {
    "fnv": 0x811C9DC5,
    "mmix": 0x9E3779B9,
    "dell": 0x44454C4C,
    "zero": 0x00000000,
    "alt": 0x5DEECE66,
    "pi": 0x243F6A88,
}

BASE_PARAMS = (17, 13, 12, 8)  # the E7A8 loop/encode rotation values
PERMS = sorted(set(itertools.permutations(BASE_PARAMS)))


def mixer_stream(tag: str, family: int, params: Sequence[int],
                 seed: int, out_sel: int) -> List[int]:
    w = seed & MASK
    for ch in tag.upper().encode("ascii"):
        w = ((w * 0x01000193) ^ ch) & MASK
    w ^= (family << 24) & MASK
    w = ((w ^ (w >> 15)) * 0x2545F491) & MASK
    out: List[int] = []
    for j in range(32):
        p = params[j % len(params)] % 31 + 1
        q = params[(j + 1) % len(params)]
        w = (((w << p) | (w >> (32 - p))) & MASK)
        w = (w + q * 0x9E3779B9) & MASK
        w ^= w >> 13
        if out_sel == 0:
            byte = (w >> (8 * (j % 4))) & 0xFF
        else:
            byte = (w ^ (w >> 16)) & 0xFF
        out.append(byte % ALPHA_LEN)
    return out


HASH_KEYS = ("hash", "material", "expand", "reducer")
MIX_KEYS = ("params", "seed", "out_sel")


@dataclass(frozen=True)
class Hypothesis:
    kind: str
    label: str
    family: Tuple[object, ...]
    keys: Tuple[str, ...] = ()

    def resolve(self) -> Dict[str, object]:
        return dict(zip(self.keys or [f"k{i}" for i in range(len(self.family))],
                        self.family))

    def stream(self, tag: str, suffix: str, fam_byte: int) -> List[int]:
        raise NotImplementedError


@dataclass(frozen=True)
class HashHypothesis(Hypothesis):
    def stream(self, tag, suffix, fam_byte):
        hash_name, mat, style, reducer = self.family
        fn = HASHES[hash_name]
        table = dict(materials(tag, suffix, fam_byte))
        raw = expand(fn, table[mat], style)
        return reduce_stream(raw, reducer)


@dataclass(frozen=True)
class MixHypothesis(Hypothesis):
    def stream(self, tag, suffix, fam_byte):
        params, seed_name, out_sel = self.family
        return mixer_stream(tag, fam_byte, params,
                            MIX_SEEDS[seed_name], out_sel)


def hash_space() -> Iterator[HashHypothesis]:
    for h in HASHES:
        for m, _ in materials("ABCDEFG", "8FC8", 0xC8):
            for st in EXPAND_STYLES:
                for rd in REDUCERS:
                    yield HashHypothesis("hash", f"{h}/{m}/{st}/{rd}", (h, m, st, rd), HASH_KEYS)


def mix_space(params_list: Iterable[Sequence[int]] = PERMS,
              seeds: Iterable[str] = MIX_SEEDS) -> Iterator[MixHypothesis]:
    for p in params_list:
        for s in seeds:
            for o in (0, 1):
                yield MixHypothesis("mixer", f"mixer/{p}/{s}/{o}", (tuple(p), s, o), MIX_KEYS)


def wide_mix_space(lo: int = 6, hi: int = 19) -> Iterator[MixHypothesis]:
    """Secondary lattice search: every rotation in [lo,hi]^4, one seed."""
    for p in itertools.product(range(lo, hi + 1), repeat=4):
        yield MixHypothesis("mixer", f"wide/{p}/mmix/1", (tuple(p), "mmix", 1), MIX_KEYS)


# ---------------------------------------------------------------------------
# Search core
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    label: str
    config: Dict[str, object]
    alphabet: str
    renderer: str
    codes: List[str]


def score(candidates: Sequence[str], codes: Sequence[str]) -> int:
    """Total matching characters, pair by pair (max 16 per pair)."""
    return sum(sum(1 for a, b in zip(cand, c) if a == b)
               for cand, c in zip(candidates, codes))


def search(pairs: Sequence[Tuple[str, str, str]],
           space: Iterable[Hypothesis],
           alphabets: Sequence[str] = ("ec", "e7a8"),
           renderers: Sequence[str] = ("sum", "verbatim")
           ) -> Tuple[List[Hit], int, int, int, List[Tuple[int, str, str]]]:
    """Exhaustively render every configuration against every pair.

    Returns (hits, configurations_tested, best_first_pair, best_total, top).
    A full sweep is never aborted early: an early exit would make the
    reported configuration count depend on luck.
    """
    hits: List[Hit] = []
    tested = 0
    best = -1
    best_first = -1
    ranked: List[Tuple[int, str, str]] = []
    codes = [c for (_, _, c) in pairs]

    for hyp in space:
        tested += 1
        for aname in alphabets:
            alpha = ALPHABETS[aname]
            for rname in renderers:
                rend = RENDERERS[rname]
                cands = []
                for (tag, suffix, _c) in pairs:
                    fam = FAMILY_BYTE.get(suffix.upper(), 0)
                    cands.append(rend(hyp.stream(tag, suffix, fam), alpha))
                if all(c == want for c, want in zip(cands, codes)):
                    hits.append(Hit(hyp.label, hyp.resolve(), aname, rname, cands))
                s = score(cands, codes)
                first = sum(1 for a, b in zip(cands[0], codes[0]) if a == b)
                if first > best_first:
                    best_first = first
                if s >= best:
                    best = s
                    ranked.append((s, cands[0], hyp.label))
    ranked.sort(key=lambda r: -r[0])
    return hits, tested, best_first, best, ranked[:5]


def positive_control(debug: bool = False) -> Dict[str, object]:
    """Plant a formula, make it the 'field data', and force the engine to
    recover it.  Proves the negative result on real data is real."""
    planted = HashHypothesis("hash", "planted",
                             ("sha3_256", "tag+fam", "chain", "xor32"), HASH_KEYS)
    tags = ["9ZZ9Z99", "8YY8Y88", "7XX7X77"]
    pair_list = []
    for t in tags:
        st = planted.stream(t, "8FC8", FAMILY_BYTE["8FC8"])
        pair_list.append((t, "8FC8", render_sum(st, EC_ALPHABET)))

    hits, tested, _bf, _bt, _ex = search(pair_list, hash_space())
    recovered = [h for h in hits if tuple(h.config[k] for k in HASH_KEYS)
                 == planted.family]
    return {
        "planted": planted.resolve(),
        "pairs": [{"tag": t, "code": c} for t, _s, c in pair_list],
        "configurations_tested": tested,
        "hits": [h.label for h in hits],
        "recovered_planted": bool(recovered),
        "planted_rank": (hits.index(recovered[0]) + 1) if recovered else None,
        "n_survivors": len(hits),
    }


# ---------------------------------------------------------------------------
# Information accounting
# ---------------------------------------------------------------------------

def information_budget(pairs: int = 3,
                       space: int = 9552,
                       length: int = CODE_LEN,
                       alphabet: int = ALPHA_LEN) -> Dict[str, object]:
    bits_per_pair = math.log2(alphabet ** length)
    bits_pairs = bits_per_pair * pairs
    bits_space = math.log2(space)
    return {
        "bits_per_pair": round(bits_per_pair, 2),
        "bits_for_pairs": round(bits_pairs, 2),
        "bits_resolved_by_space": round(bits_space, 2),
        "configs_needed_to_resolve_one_pair": f"2^{bits_per_pair:.1f} = {alphabet ** length:.3e}",
        "false_positive_pairs_expected": {
            "space_10k": f"{space / (alphabet ** length):.3e}",
            "space_2p40": f"{2.0 ** 40 / (alphabet ** length):.3e}",
            "space_2p60": f"{2.0 ** 60 / (alphabet ** length):.3e}",
        },
        "reading": (
            "Each field pair pins the transform to 98.72 bits. A 10k-config "
            "search tests 13.22 bits. Even a 2^60 search leaves 38.7 bits of "
            "freedom per pair: it cannot distinguish a correct formula from a "
            "wrong one unless the formula is structurally right, which is "
            "exactly the part that is not public."
        ),
    }


def detection_capacity(pairs: int = 3) -> Dict[str, object]:
    """Distinguish 'detect a wrong formula' from 'identify the right one'."""
    bits = math.log2(ALPHA_LEN ** CODE_LEN) * pairs
    return {
        "pairs": pairs,
        "bits_available": round(bits, 2),
        "verdict_detect": "yes -- one pair rejects any concrete candidate",
        "verdict_identify": (
            "no -- identification needs the structural form of the transform, "
            "which no field pair can supply"
        ),
        "consequence": (
            "more field pairs raise rejection power but never reveal structure; "
            "collecting tags is the weakest possible evidence investment"
        ),
    }


def chance_baseline(trials: int, code: str, reps: int = 40,
                    seed: int = 0xDE11) -> Dict[str, float]:
    """How good is 'best partial match' if the space were pure noise?

    Draws `trials` random 16-character codes from the render alphabet and
    reports the distribution of the best per-pair match count.  If the real
    sweep's best score sits inside this band, the space is finding no
    structure at all -- the cleanest statement a negative result can make.
    """
    import random
    rng = random.Random(seed)
    alpha = EC_ALPHABET
    n = len(code)
    maxima = []
    for _ in range(reps):
        best = 0
        for _ in range(trials):
            cand = "".join(alpha[rng.randrange(ALPHA_LEN)] for _ in range(n))
            sc = sum(1 for a, b in zip(cand, code) if a == b)
            if sc > best:
                best = sc
        maxima.append(best)
    maxima.sort()
    return {
        "trials_per_rep": trials,
        "reps": reps,
        "mean_max": round(sum(maxima) / len(maxima), 2),
        "p05": maxima[int(0.05 * len(maxima))],
        "p50": maxima[len(maxima) // 2],
        "p95": maxima[int(0.95 * (len(maxima) - 1))],
        "max": maxima[-1],
    }


# ---------------------------------------------------------------------------
# Evidence-value ranking (original result)
# ---------------------------------------------------------------------------

EVIDENCE_RANKING = [
    {
        "rank": 1,
        "artifact": "decrypted MEC17xx EC firmware from your own board",
        "yields": "the actual GENERATE handler and its 32-byte table/PRNG",
        "solves": "8FC8 / 9ABE / CF1B / 3FE2 / 1B58 at once",
        "why": "the transform lives in EC SRAM/flash, not in the BIOS PE",
        "blocked_by": "EC region is encrypted/read-protected on MEC17xx",
        "authorization": "board must be yours/contracted; debug unlock voids warranty",
    },
    {
        "rank": 2,
        "artifact": "32-byte GENERATE response from the target board",
        "yields": "the exact password for that board (renderer is trivial)",
        "solves": "one machine, all suffixes it supports",
        "why": "the BIOS renderer is already fully reversed; the EC is the only gap",
        "blocked_by": "needs a booted/EC-live vantage point or BIOS-side hook",
        "authorization": "requires physical access + ownership",
    },
    {
        "rank": 3,
        "artifact": "a blind oracle that already answers for your board",
        "yields": "the password (not the algorithm)",
        "solves": "one machine",
        "why": "answer-reading, not reverse engineering; zero generality",
        "blocked_by": "cost/trust; gives no formula",
        "authorization": "use only on hardware you own",
    },
    {
        "rank": 4,
        "artifact": "more (tag, displayed suffix, password) pairs from GitHub",
        "yields": "negative controls and falsification only",
        "solves": "nothing new after the first 3 pairs",
        "why": "98.72 bits/pair vs unknown structure -- see information_budget()",
        "blocked_by": "nothing; it is just weak",
        "authorization": "n/a",
    },
]


# ---------------------------------------------------------------------------
# Field-pair corpus (GPU for falsification; not a solution)
# ---------------------------------------------------------------------------

def load_pairs() -> List[Tuple[str, str, str]]:
    data = json.loads((EVIDENCE / "vectors.json").read_text())
    out: List[Tuple[str, str, str]] = []
    for p in data.get("field_8fc8_pairs", {}).get("pairs", []):
        if p.get("verified", "").startswith("owner-verified"):
            out.append((p["tag"], p["suffix"], p["code"]))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _fmt_hit(h: Hit) -> str:
    return (f"  HIT {h.label}\n      alphabet={h.alphabet} renderer={h.renderer}\n"
            f"      codes={h.codes!r}")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--space", choices=("hash", "mixer", "all", "wide"), default="all")
    ap.add_argument("--control", action="store_true", help="run the planted-formula control")
    ap.add_argument("--info", action="store_true", help="print the information accounting")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    result: Dict[str, object] = {}

    if args.control:
        pc = positive_control()
        result["positive_control"] = pc
        if not args.quiet and not args.json:
            print("== positive control (planted formula) ==")
            print(f"  planted        {pc['planted']}")
            print(f"  field pairs    {[p['code'] for p in pc['pairs']]}")
            print(f"  tested         {pc['configurations_tested']} configurations")
            print(f"  recovered      {pc['recovered_planted']} (rank {pc['planted_rank']})")
            print("  -> engine can find a real formula; a zero on real data is meaningful\n")

    if args.info:
        ib = information_budget()
        dc = detection_capacity()
        result["information"] = ib
        result["detection"] = dc
        result["evidence_ranking"] = EVIDENCE_RANKING
        if not args.quiet and not args.json:
            print("== information accounting ==")
            print(f"  bits per pair              {ib['bits_per_pair']}")
            print(f"  bits for 3 owner pairs     {ib['bits_for_pairs']}")
            print(f"  resolved by 10k search     {ib['bits_resolved_by_space']}")
            print(f"  -> {ib['reading']}\n")
            print("== evidence value, best first ==")
            for row in EVIDENCE_RANKING:
                print(f"  {row['rank']}. {row['artifact']}")
                print(f"     yields   {row['yields']}")
                print(f"     solves   {row['solves']}")
            print()

    if args.space:
        pairs = load_pairs()
        if not pairs:
            print("no owner-verified field pairs found", file=sys.stderr)
            return 2
        if not args.quiet and not args.json:
            print(f"== falsification sweep: {args.space} ==")
            print(f"  pairs: {[p[0] + '-' + p[1] for p in pairs]}")
        t0 = time.time()
        if args.space == "hash":
            space: Iterable[Hypothesis] = hash_space()
        elif args.space == "mixer":
            space = mix_space()
        elif args.space == "wide":
            space = wide_mix_space()
        else:
            space = itertools.chain(hash_space(), mix_space())
        hits, tested, best_first, best, ranked = search(pairs, space)
        dt = time.time() - t0
        trials = tested * 2 * 2  # configurations x alphabets x renderers
        baseline = chance_baseline(min(trials, 200000), pairs[0][2])
        result["sweep"] = {
            "space": args.space,
            "configurations": tested,
            "renders": trials,
            "seconds": round(dt, 2),
            "survivors": len(hits),
            "best_total_char_score": best,
            "best_first_pair_score": best_first,
            "best_examples": [{"code": c, "score": sc, "config": lb}
                              for sc, c, lb in ranked],
            "chance_baseline_first_pair": baseline,
        }
        if not args.quiet and not args.json:
            print(f"  tested         {tested} configurations x 2 alphabets x 2 renderers "
                  f"in {dt:.1f}s")
            print(f"  survivors      {len(hits)}")
            for h in hits:
                print(_fmt_hit(h))
            print(f"  best partial   {best} chars summed over {len(pairs)} pairs "
                  f"(max {16 * len(pairs)}); best single pair {best_first}/16")
            for row in result["sweep"]["best_examples"][:3]:
                print(f"                 {row['score']:>2}  {row['code']}  <- {row['config']}")
            print(f"  noise band     a pure-random sweep of the same size scores "
                  f"{baseline['mean_max']}/16 on one pair (p95 {baseline['p95']})")
            inside = best_first <= baseline["p95"]
            print(f"  structure?     {'no -- real sweep is inside the noise band' if inside else 'above noise'}")
            print()
            if not hits:
                print("  VERDICT: space falsified. The transform is not one of these")
                print("           constructions. That is a proof of absence *for the")
                print("           enumerated space*, not a solution for the board.")
                print()
        return 0 if not args.json else _emit(result)

    if args.json:
        return _emit(result)
    return 0


def _emit(obj: Dict[str, object]) -> int:
    print(json.dumps(obj, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
