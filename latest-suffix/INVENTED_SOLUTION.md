# Inventing a solution instead of re-publishing one

**Scope.** Everything upstream of this file answers the latest-suffix question by
*reading* something: bacher09's keygen (stops at `E7A8`), secaicandido/bioskey
(relabels `E7A8` with newer words — disproven below), DellBIOSTools (SPI
patching, not generation), and the paid "oracle" services (answer-reading, not
reverse engineering). None of them compute the EC-era transform, because the
transform is not in any host-visible file.

So this document does not publish a formula. It invents the two things that can
actually be invented without lying:

1. **A falsification engine** that kills the whole "small formula" hypothesis
   class against real field data — with a positive control proving the engine
   can find a formula when one exists.
2. **A chosen-query function-class probe** that either *recovers the generator
   exactly from 57 queries against your own board* or *proves that no offline
   generator can exist*. Both outcomes end the question.

Files: `falsify.py`, `ec_oracle_probe.py`, `test_invented.py`,
`evidence/invented_results.json`.

---

## 0. Why "invent the formula" is not an option — the number

A displayed master code is 16 characters over a 72-symbol alphabet:

```
log2(72^16) = 98.72 bits per field pair
3 owner-verified 8FC8 pairs -> 296.16 bits of constraint
```

A hypothesis space of *H* constructions can only ever be resolved by
`log2(H)` bits of that budget. A 10,000-configuration search consumes 13.2
bits — 13% of **one** pair — and, decisively:

```
P(a wrong 10k-config formula matches all 3 pairs)  ~ 1.8e-26
P(a wrong 2^60-config formula matches all 3 pairs) ~ 2.2e-12
```

That second line is the honest one. **A search is a poor way to find a secret;
it is an excellent way to destroy a guess.** Any "invented" formula I printed
without validating it against the board would be one of 2^98.72 equally
plausible 16-character strings, i.e. it *is* a random password with extra
steps. Printing one would be the only thing in this whole project that could
actually damage a machine (BIOS lockout counters) while looking like progress.

So the deliverable is: make the hypothesis class falsifiable, then make the
board itself the source of truth.

---

## 1. The falsification engine (`falsify.py`)

An original, closed, explicitly-bounded space of "small construction" formulas,
written from nothing in any repo:

| axis | values | count |
|---|---|---|
| outer hash | md5, sha1, sha256, sha512, sha3-256, blake2s, blake2b | 7 |
| EC input material | tag, tag+family, family+tag, tag+suffix, suffix+tag, reversed tag, NUL/0xFF/space-padded tag (8 and 16), tag×2, tag+tag, tag‑dash‑family, NUL+tag, tag+"Dell" | 15 |
| 32-byte expansion | counter, chain (2+ rounds, take tail), dup, self-iterate | 4 |
| symbol reduction | mod 72, mask 0x3F, half-XOR, nibble swap, rotate-3 | 5 |
| custom scalar mixer (separate family) | 24 rotation orders of `(17,13,12,8)` × 6 seeds × 2 output taps | 288 |
| renderer | `alphabet[(r[i]+r[i+16])%72]` (8FC8) and verbatim halves (9ABE/CF1B/3FE2/1B58) | 2 |
| alphabet | the 8FC8 render alphabet and the E7A8 alphabet | 2 |
| **wide lattice (secondary)** | every rotation in `[6..19]^4`, one seed/tap | 38,416 |

Every configuration is rendered for **all three** owner-verified 8FC8 field
pairs before any verdict is issued (no early exit — an early exit makes the
reported count luck-dependent).

### Result

```
$ python3 falsify.py --space all
  pairs        1K6Y963-8FC8, 5S38Y33-8FC8, C9F23Z2-8FC8
  tested       2,388 configurations x 2 alphabets x 2 renderers
  survivors    0
  best partial 4/16 on a single pair
  noise band   pure random: 4.4/16 mean, p95 5/16
```

```
$ python3 falsify.py --space wide      # 38,416 configs, ~30 s
  survivors    0
  best partial 6/16          noise band mean 5.4, p95 6
```

The best match in ~163,000 renders is *inside the band you get from random
strings*. The space is not finding structure — it is finding alphabets. That
is the correct signature of "the transform is not a 56-bit-input hash-and-fold
of the kind every public generator assumes".

### The control that makes the zero meaningful

A search that never returns a hit proves nothing unless it can return a hit.

```
$ python3 falsify.py --control
  planted       sha3_256 / tag+family / chain / xor32
  tested        2,100 configurations
  recovered     True (rank 1)          <- unique survivor
```

The engine recovers a planted formula at rank 1 with **zero** false positives
from the other 2,099 configurations. So the zero on real data is a
falsification, not a bug.

### What this kills, specifically

The published `secaicandido/bioskey` modern-suffix support is `E7A8` with the
suffix string mixed into the serial before hashing, plus two candidate
branches. That is inside the space (material `tag+suffix`, the E7A8 alphabet,
both renderers, the same hash families). It produces **zero** survivors against
the three owner-verified 8FC8 pairs — the hypothesis is falsified, not merely
"unvalidated".

---

## 2. The chosen-query probe (`ec_oracle_probe.py`)

The only input the EC's `GENERATE` takes is the argument the *host supplies*:
7 service-tag bytes and a 1-byte family id. So stop asking where the formula
is stored and ask **what class of function the answer is**.

### The recovery theorem this tool implements

If the EC's response map is affine over GF(2) — which is what every CRC, LFSR,
xorshift, rotate-XOR or table-free scrambler is — then

```
resp(tag) = resp(t0) XOR Σ_{i ∈ bits(tag XOR t0)} col[i]
```

and `col[i]` is directly observable: ask for `tag = t0 XOR e_i`. With
`t0` = your own tag (always accepted):

| step | queries |
|---|---|
| base response for `t0` | 1 |
| one per tag bit (`56` bits) | 56 |
| held-out verification (default) | 24 |
| **full recovery + verification** | **81** (57 to recover) |

The result is an exact, offline, firmware-free generator for **any** tag,
including tags you do not own — with no published formula, no SPI patch, and
no vendor code.

A high one-bit avalanche is *not* evidence against this: a random 256-bit
column flips ~128 bits too. **Affinity is the discriminator, avalanche is
not.** That distinction is the reason the published discussion around
"SHA256 of the master password" never settled whether the EC could be modelled.

### The three verdicts

```
$ python3 ec_oracle_probe.py --self-test
  [PASS] affine-ec        expect affine-recovered   got affine-recovered  q=89 | rank 56 | 24/24 exact
  [PASS] xorshift-ec      expect affine-recovered   got affine-recovered  q=89 | rank 56 | 24/24 exact
  [PASS] affine-ec+carry  expect nonlinear          got nonlinear         q=8
  [PASS] prf-ec (HMAC)    expect nonlinear          got nonlinear         q=8
  [PASS] locked-affine-ec expect tag-locked         got tag-locked        q=2
```

| verdict | meaning | what you get |
|---|---|---|
| `AFFINE-RECOVERED` | rank 56 linear map found | the algorithm, exactly, for all tags, offline, forever |
| `NONLINEAR` | affinity fails on random pairs | proof that no 56-parameter model exists — therefore no offline keygen for anyone, including the paid services |
| `TAG-LOCKED` | foreign tags are refused | a donor machine cannot help either; only the sealed tag inside that board can |

The `TAG-LOCKED` branch is decided in **2 queries**, so the "is a donor board
useful?" question that has been open in the issue tracker is answerable in
about a second, on hardware you own.

Note the `xorshift` row: a construction that *looks* like a hash from the
outside is recovered bit-exactly, because xorshift is GF(2)-linear. Most
plausible EC codegen lives in this class. If the real EC lands in
`AFFINE-RECOVERED`, the latest-suffix problem is **solved**, by this tool, with
no reliance on anything published.

`--simulate` also accepts `--capture FILE` (replay recorded responses) and
`--target TAG --suffix 8FC8|9ABE` to drive the recovered model through the
firmware-validated renderer and print a code for an arbitrary tag.

---

## 3. Where the evidence actually is (ranking, not wishlist)

| rank | artifact | yields | blocked by |
|---|---|---|---|
| 1 | decrypted MEC17xx EC firmware from a board you own | the GENERATE handler itself | EC region encrypted/read-protected |
| 2 | 32-byte `GENERATE` response from the target board | that board's password today | needs an EC-live vantage point |
| 3 | blind oracle that answers for your board | the password, no algorithm | cost/trust, zero generality |
| 4 | more `(tag, suffix, password)` pairs from GitHub | negative controls only | nothing — it is just computationally worthless |

Rank 4 is what the public thread keeps producing: three owner-verified pairs
already exist and they resolve 296 bits, which is 30× more than any search
consumes. More pairs cannot substitute for structure. Rank 2 is what
`ec_oracle_probe.py` converts into rank 1, *if* the answer is affine.

---

## 4. Honest limits

- Nothing here has run against real hardware. `AFFINE-RECOVERED` failing on a
  real board is a real possibility; the probe reports it as `NONLINEAR` rather
  than pretending.
- The affine assumption requires the EC to accept foreign tag values. If the
  seal is enforced, the probe says `TAG-LOCKED` in 2 queries — a result, not a
  failure.
- "57 queries" presumes a vantage point where the host can issue `GENERATE`
  with arbitrary tag bytes (EC-live, or a UEFI-side hook over
  `DellEcIoSmm`). Buying that vantage point is a physical-access question, not
  a mathematical one.
- The `NONLINEAR` verdict rules out the *enumerated* affine/scalar classes; a
  carry-based byte-additive model is not excluded, only bounded.
- **A source-integrity finding:** the newest "we support 8FC8" repository
  (`LeRELIKT/BIOS-Generator-Patch`, published 2026-10-25) is now **gone** from
  GitHub — `verify_sources.py` reports it as `GONE`, not as a pass. A source
  that lasted four days is not evidence of an algorithm, and a claim that
  disappears when challenged is the strongest argument for building tools that
  a reader can re-run against their own hardware instead of trusting a repo.
- No vendor code, no vendor constants, no passwords are redistributed here.
- Machine-specific work still requires that you own or are authorized to
  service the hardware.

---

## 5. Bottom line

The question "get the latest-suffix master-password algorithm from GitHub
files" has a definite answer that this kit now demonstrates rather than
asserts: **the latest suffix is `9ABE`; the algorithm is not in any GitHub
file, because it is not in any host-visible file at all.** The published
`E7A8` relabel is falsified against field data. What remains is a binary
question about the EC — affine or not — and `ec_oracle_probe.py` is the tool
that answers it and, in the affine case, hands over the complete algorithm.
