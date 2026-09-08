# How carrier unlock codes actually work

Notes from reading [`alexanderritola/Go-Unlock-Code-Calculator`](https://github.com/alexanderritola/Go-Unlock-Code-Calculator)
at `master` @ `8cabc40` (2013-01-28), cross-checked against published vectors.
A runnable port lives next to this file in [`unlock.py`](./unlock.py).

Everything here describes schemes from roughly 2007–2014. They are dead on any
modern device; the last section explains why.

---

## 1. What the "unlock code" is

A SIM/network-locked handset stores, in the **modem's non-volatile memory**
(not the app processor, not the SIM), three things:

| Item | Meaning |
| --- | --- |
| **NCK** (a.k.a. NP, network control key) | the code that permanently removes the carrier lock |
| **SPCK / SP** | a secondary/service code, usually a fallback or a superuser path |
| **counter** | remaining attempts; hitting 0 hard-locks the device |

Insert a SIM whose MCC/MNC is not on the allowed list → the modem refuses to
register and asks for the NCK. Type the right code → the modem clears the lock
flag in NV and never asks again.

The security question is therefore exactly one thing: **how does the modem
decide a typed code is correct?**

### The design that made calculators possible

In the pre-2014 generation the modem contained no secret of its own. It
contained a *public algorithm* and evaluated

```
accept(typed_code)  ⟺  typed_code == f(IMEI)
```

where `f` is fixed for the whole product family — the same for every unit that
ever rolled off the line. The manufacturer ran `f` on a server to produce codes
for carriers; but because `f` was deterministic, **extracting `f` from one
firmware image once was enough to generate valid codes for every device in that
family, forever.** That extraction is what produced the calculator sites and
this repo.

Two sub-variants exist:

* **Pure IMEI-derived** — `f` uses only the IMEI plus constants baked into the
  binary (ZTE v1/v2/v3, Huawei v1, Alcatel C700).
* **Secret-table derived** — `f` also needs a per-model secret byte string
  shipped in the firmware (BlackBerry MEP, the ZXIC/H220m map). Still offline
  and still breakable, but you have to find the table first.

Modern devices invert this: the handset stores a *hash* and the code is
recovered by brute-forcing a small space, or the code is issued by a server
that holds a secret the handset never sees. Neither is computable from the
IMEI alone.

---

## 2. The five algorithms in this repo

### ZTE v1 — `ZTE.go zteOld()`

The oldest and weakest. It drops the 3-digit TAC prefix and the Luhn check
digit, works on the 12 middle digits, and mixes them with a fixed vector:

```
d        = imei[3:15]                      # 12 digits
crosssum = sum(d)
NCK[i]   = (d[i]*crosssum + d[11-i]*8 + magic[i]) % 10
SPCK[i]  = (NCK[i] + d[11-i]) % 10         # magic = [6,8,8,9,5,0,0,0,0,0,0,0]
```

No cryptography at all — a linear combination mod 10. `SPCK` is a trivial
function of `NCK`, so it leaks nothing extra.

**Verified end-to-end.** A 2014 blog quotes `tools.texby.com` returning
`NCK 185553270348 / SPCK 184709110429` for an unstated IMEI. Because
`SPCK[i] = (NCK[i] + d[11-i]) % 10` is invertible, the published pair alone
gives the device's digits back: `imei[3:15] = 181049652900`, crosssum 45.
Running the repo's own magic vector over that reproduces the published NCK
*and* SPCK exactly. See `unlock.py --self-test`.

### ZTE v2 / v3 — `ZTE.go zteB03()` / `zteB04()`

MD5 of the IMEI, then fold the two halves together:

```
pre    = md5(imei)                          # 16 bytes
NCK[i] = ((pre[i] + pre[i+8]) * 9) / 255              # v2 / B03
NCK[i] = ((pre[i] + pre[i+8] + pre[i+4] + 40) * 9) / 255   # v3 / B04
```

Integer division by 255 after multiplying by 9 maps 0..255 onto **0..9**, so the
NCK is 8 characters drawn from `0`–`9`. v3 is v2 with an extra term and an
additive constant — a trivial iteration, which is why the two coexist in one
file.

Two things worth knowing when reading the Go:

* `& int64(0xFF)*int64(0x09)` looks like a precedence bug. It isn't. In Go `*`
  and `&` are *both* precedence level 5 and left-associative, so it parses as
  `(sum & 0xFF) * 9` — the intended reading.
* The maximum key value is 9, not 8. My first invariant check assumed 0..8 and
  failed on a real IMEI; `(255*9)/255 == 9`.

### Huawei v1 — `Huawei.go`

The best-known one, for E160/E170/E589-class USB modems. Two fixed passphrases
are MD5'd and hex characters 8..24 become the per-purpose salt:

```
md5("hwe620datacard") = a32fe72c 5e8dd316726b0335 d5513ba0  -> unlock salt
md5("e630upgrade")    = aa91cee2 97b7bc6be525ab44 cdc63be0  -> flash salt
```

Then:

```
digest = md5(imei + salt)
b[i]   = digest[i] ^ digest[i+4] ^ digest[i+8] ^ digest[i+12]   # 4 bytes
code   = int(b)  & 0x1FFFFFF  | 0x2000000
```

The `& 0x1FFFFFF | 0x2000000` is cosmetic — it forces the result into
`0x02000000..0x03FFFFFF` so every code is exactly 8 digits with a leading 3, 4,
5 or 6. It also throws away ~1 bit of entropy.

**Verified** two ways: the salts reproduce with coreutils `md5sum`, and the port
agrees with the independent 2010 Python reference (`hvera.wordpress.com`) on
40,000 (IMEI, salt) pairs.

### BlackBerry MEP — `Blackberry.go` + `findMEP.go`

The only genuinely cryptographic one here. `findMEP.go` is 370 KB of tables:

* `supportedMEP` — **232** `MEP-nnnnn-nnn` keys, each a 16-byte secret (224
  distinct values)
* `supportedPRD` — **7,110** `PRD-nnnnn-nnn` product codes, each an alias onto
  one of those secrets

Then:

```
Pass[0..15] = static[i] ^ MEP[i]        # static = 16 27 99 C2 C8 99 B8 C9 DE ED 77 A2 62 D2 66 5E
Pass[16..63] = 0
for n in 1..5:
    MEPn = HMAC-SHA1(key=Pass, msg=imei || "0" || n)
```

`makeSHA1` hand-rolls the HMAC — ipad `0x36`, opad `0x5C`, 64-byte key — which
is exactly `hmac.new(key, msg, sha1)`. Verified against the stdlib for all five
slots. `makeCode` then keeps the last decimal digit of the first 16 digest
bytes (first 8 for a short list of MEPs), giving a 16- or 8-digit code per
slot.

The weakness is not the hash — it's that `Pass` is a **fixed constant per
model**, sitting in plaintext in the firmware.

### Alcatel C700 family — `Alcatel.go`

SHA1 plus per-model obfuscation:

1. `simei = imei + "0"`, swap each adjacent digit pair, prepend `"08"` → 18 chars
2. split into 9 two-char chunks, reorder them by a 9-digit model-specific
   permutation
3. SHA1 over 28 bytes: `tag || swapped || swapped || permuted`
4. XOR five digest bytes together, four times, indices picked from a
   model-specific 20-entry table → 4 bytes → read as a decimal number

Two constants differ between NCK and SPCK (`3C`/`E2` for C700, `8F`/`BE` for
C820, …); the permutation and XOR table are shared. The repo hard-codes five
model profiles covering ~14 model names. No published vector found, so this one
is ported and runs, but is **not verified against a device**.

---

## 3. Why none of this applies to a modern ZTE device

The firmware in this repository — `machine-recovery-image-selinux-sdxprairie.ubi`
— belongs to a **ZTE MC801A** (build path `Soft4_P82M_SASTCMC801A_uSDK`), a
2020 Snapdragon X55 (`sdxprairie`) 5G CPE. That is ~7 years and several
algorithm generations past anything above. I extracted its UBIFS volume
(95 LEBs, 2,181 files) and grepped for `nck|simlock|networklock|unlock_code`:
**zero hits.** The recovery image has no lock logic; the check lives in the
modem firmware, which is not in this file.

For contrast, a *2019-era* ZTE-family device (ZXIC ZX297520V3 / Hisense
H220m) still uses an offline IMEI-derived scheme — an 8-wide sliding window
sum over a 10-entry digit substitution table, mod 10 — and it still reproduces
its published example (`987654321098767 → 16159363`). But by the SDX55
generation the published accounts describe codes issued by a manufacturer-side
pipeline keyed on data the handset never exposes, i.e. exactly the inversion
that ends calculators. **Unverified here** — I have no MC801A modem firmware to
check against.

---

## 4. Samsung / AT&T — current models

`samsung_att.py` and `models/att-samsung.json` cover this. **The headline is
that there is no algorithm to add.** Everything in section 2 is an offline,
IMEI-derived function lifted out of 2007–2014 firmware; current AT&T Samsung
hardware does not work that way, and I could not find a public algorithm that
does. `samsung_att_nck()` raises `NotCalculable` rather than returning a number.

### What actually happens on a current AT&T Galaxy

| | Legacy Samsung | Current Samsung (AT&T) |
| --- | --- | --- |
| NCK length | 8 digits | **16 digits** (e.g. `NCK=2738272959528493`) |
| Companion codes | SPCK | **MCK** (defreeze) and **RGCK** (regional) |
| Where the code comes from | **stored in EFS** at a fixed offset, not derived | **AT&T/Samsung server**, after an eligibility check |
| Alternate path | none | **server-side / OTA unlock** — nothing is typed at all |
| Entry sequence | `#7465625*638*CODE#`, `#0111*CODE#` | `*#865625#` → Network Lock → 16 digits |
| Attempts | ~4–5 | **5 or 10** depending on model, then frozen |

Sources: AT&T's own `ATTDeviceUnlockCodeInstructions.pdf` documents the
`*#865625#` flow and the 16-digit code; a code vendor documents the
NCK/MCK/RGCK triple at 16 digits.

### There is no Samsung keygen, and there never was

This is the one brand where the keygen instinct is simply misapplied. For ZTE,
Huawei, Alcatel and the H220m-class devices in `unlock.py`, the handset *derived*
its code from the IMEI, so recovering the algorithm gives you a generator.
Samsung never did that. Samsung **stored** the code as eight ASCII digits inside
the EFS partition, written at the factory. There is no function to invert.

The proof is in the two canonical Galaxy S 4G tools, both public and both
GPL-3.0, which I read rather than summarised:

* `fbis251/sgs4g-unlock-code-finder` (ANSI C) — `readUnlockCode()` does `fseek`
  to `CODE_LOCATION` and `fread`s 13 bytes. That is the whole mechanism.
* `fbis251/Galaxy-S-Unlocker-for-PC` (D) — same layout, plus validation.

`grep -i imei` across both projects returns **nothing**. Neither program accepts
an IMEI as an argument, because an IMEI would be useless to them.

The layout, from `unlocker.h` and `unlocker.d` verbatim:

```
0x1468   0xFF                     validation byte
0x1469   byte 0 of 13             lock status: 0x00 unlocked, 0x01 locked
0x146E   8 bytes, ASCII '0'-'9'   THE UNLOCK CODE   (0x1469 + 5)
```

`samsung_nvdata.py` ports this — extractor plus the stricter validation — with
27 self-checks. It reads the code back out of an `nv_data.bin` for
SGH-T959V / SGH-T959W:

```
$ python3 samsung_nvdata.py nv_data.bin
code at 0x146E  : 27382729
lock status   : Locked
```

That is the closest thing to a Samsung keygen that has ever existed, and note
what it is: a *reader*. It recovers a value that was already sitting there. Every
model after this generation stopped exposing the code as plaintext, and from
there the only copy is on the carrier server — which is the state the A53 is in.

### Why a calculator cannot exist here

The general shape of a modern scheme was described publicly on XDA in 2017 for
handsets holding `SALT` and `HASH` in a protected trim area:

```
h = sha256(NCK || SALT)
repeat 9 more times: h = sha256(h)
accept iff h == HASH
```

The handset can only *check* a code, never derive one — the NCK is effectively
a preimage, so the carrier is free to issue random codes and no amount of
firmware analysis yields a generator. (`samsung_att.py` implements this
verifier and benchmarks it; note it is documented for Sony-family trim-area
devices — **Samsung's current internal scheme is not public**, and I have not
found it.)

I measured the brute-force angle rather than hand-waving it: a 10-round chain
runs at **~250,000 guesses/s** on one core here, and the 16-digit space is
10^16 ≈ 2^53.2. So a single GPU could average-case it in weeks — but that is
irrelevant, because you would first need `SALT` and `HASH`, which live in
device-protected storage, and anyone who can extract those can simply clear the
lock flag. **The code is a lookup, not a computation.**

### Why the refusal is the safe behaviour

A wrong NCK does not fail harmlessly on Samsung. AT&T's instructions state 5 or
10 attempts depending on model; after that the baseband freezes and requires an
**MCK**, which is *also* server-issued. A calculator that emitted
plausible-looking 8-digit numbers would be a brick generator for exactly the
phones its users are trying to save. Every "free Samsung MCK generator" I found
in research is a scam or malware.

### The AT&T model table

`models/att-samsung.json` — 28 entries: 25 tagged `source: "att"` and 3 tagged
`source: "press"`; 24 carry a model number, the remainder are phones AT&T lists
without a number I could retrieve. `att` entries were read off AT&T's own
device-support selector (which lists **115 Samsung phones**); `press` entries
come from trade coverage and are **not** confirmed against AT&T. The self-test
enforces that every entry is sourced and that model numbers are unique.

```
$ python3 samsung_att.py --models S26
SM-S942U     Galaxy S26               2026 att
SM-S947U     Galaxy S26 Plus          2026 att
SM-S948U     Galaxy S26 Ultra         2026 att
?            Galaxy S26 FE            2026 att
```

The table is **not exhaustive** — `_meta.complete` is `false` and the self-test
asserts it stays that way. A model missing from this file is a gap in the file,
not a fact about the device. It originally started at 2023 and silently missed
the 2022 Galaxy A53 5G (`SM-A536U`), which is now included.

### A TAC-reading trap worth recording

Reading a device off its IMEI has one sharp edge. Before 2004 the TAC was 6
digits plus a 2-digit Final Assembly Code, and the usual heuristic for legacy
IMEIs is:

```
starts '01' and first8 < '01015900'  -> 6-digit TAC
starts '35' and first8 < '35150100'  -> 6-digit TAC
```

That rule disambiguates genuinely old handsets. **It is not a claim that the
8-digit space below those thresholds is frozen** — GSMA allocates 8-digit TACs
there today. `350012623050961` is a 2022 AT&T Galaxy A53 5G with 8-digit TAC
`35001262`; run through the legacy rule it becomes 6-digit TAC `350012` + FAC
`62`, and a stale 2018 phone-types list maps `350012` to "Kapsch AG GSM-R MT",
a railway cab radio. That misidentification was stated here with full
confidence and was wrong.

`samsung_att.py` now defaults to 8 digits, *flags* the legacy reading when the
number falls in that range without applying it, and explains the trap in the
output. `--imei` is the entry point:

```
$ python3 samsung_att.py --imei 350012623050961
IMEI        : 350012623050961
  TAC       : 35001262   (8 digits -- the default and correct reading)
  model     : Galaxy A53 5G (SM-A536U)
  tac source: user-reported 2026-09-08; NOT confirmed against the GSMA database
  ...
```

TAC coverage in the JSON is deliberately sparse, and every TAC carries a
`tac_source` field naming where the binding came from. The self-test asserts
that an unverified TAC always surfaces its provenance rather than presenting
itself as a database hit.

`SM-S942U/S947U/S948U` are the S26 / S26+ / S26 Ultra; `SM-F976U` (Z Fold8) and
`SM-F776U` (Z Flip8) are flagged `press` because AT&T lists those phones without
a model number I could capture. Entries with `model: null` are phones AT&T lists
whose numbers I did not retrieve — I left them blank rather than guess.

### Practical helper: `a53_att.py`

Since the code itself cannot be produced, the useful work is removing every
other obstacle. `a53_att.py` is a guided walkthrough for one specific handset —
the AT&T Galaxy A53 5G — with sources cited inline.

The detail that actually changes the procedure: **the A53 has no eSIM, in any
region.** Samsung's A-series did not get eSIM until the A54 (March 2023). So the
unlock cannot be tested or completed with an eSIM — a physical nano-SIM from
another carrier has to be in hand before starting. Carrier variants are also
single-SIM, so there is no second slot to test with.

```
$ python3 a53_att.py                 # full walkthrough
$ python3 a53_att.py frozen          # jump to a failure path
$ python3 a53_att.py --self-test     # 59 checks, 0 failures
```

It covers: model confirmation against all 11 A53 variants, the lock-status check
to run *first*, AT&T's eligibility rules, the request flow including the 24-hour
email expiry, code entry (MCK first if supplied — it reports "unsuccessful" by
design and costs nothing), and five failure paths. Its self-test asserts that
nothing in it advises guessing a code.

#### The code verifier — the one thing that can still go wrong for you

Since the NCK exists only in AT&T's email, the residual risk is entirely at the
point of entry: a mistyped digit, or a code bought from a reseller. Both cost an
attempt out of 5–10, and the budget is not recoverable without another
server-issued code (the MCK). So `a53_att.py --check` gates that entry.

```
$ python3 a53_att.py --check 40760382
code      : 40760382
length    : 8 (expected 16)
VERDICT: DO NOT ENTER -- this will cost an attempt
  BLOCK  8 digits. That is the pre-2019 Samsung format, and it is what most
         third-party resellers sell. ...
```

It blocks: wrong length, letters in the code, all-same-digit runs, known
placeholder values, anything containing or derived from the IMEI (the signature
of the dead 2010-era calculators), and model-number filler. It warns on long
ascending/descending runs and palindromes — statistically odd for a real NCK,
but not impossible, so they are flagged rather than refused. Exit status is 0
for enter, 1 for caution, 2 for do-not-enter, so it can be used as a gate.

Crucially it never claims a code is *correct*. Nothing outside AT&T's server can
know that. What it establishes is that the transcription is clean and the value
is not one of the well-known junk patterns — which is where attempts actually go.

`--log-fail` / `--log-success` / `--attempts` track the budget in
`.a53_attempts.json` (gitignored), storing only a 4-digit prefix per failure so
the file is not a list of codes.

### AT&T eligibility (from att.com/legal, KM1258553)

Not reported lost/stolen/fraud · contract or installment plan completed (pay off
early, re-request after 24h) · not active on another AT&T account · 14 days
after an early upgrade (30 for business) · **60 days of active service with no
past-due balance** · AT&T PREPAID needs **6 months** · military exempt from
installment/contract completion with TCS/PCS orders · business devices need
company authorisation.

Request at <https://www.att.com/deviceunlock>, confirm the email, then either
nothing happens (OTA) or you get a code.

---

## 5. Bugs in the upstream Go repo

Found by reading; the package cannot be compiled in this sandbox (no Go
toolchain reachable — `go.dev`, `dl.google.com`, `storage.googleapis.com` and
mirrors all fail TLS from here), so items marked ⚠ are spec-based, not
executed.

| # | Location | Problem |
| --- | --- | --- |
| 1 | `main.go:23` | Calls `todo()`, which is **defined nowhere** in the repo. All 17 `func` declarations were enumerated; none is named `todo`. **The repo does not build as committed.** |
| 2 | `main.go:21` | `userArgs[1]` with no `len(os.Args)` guard → index-out-of-range panic on `./calc`. |
| 3 | `findMEP.go:7363` `getSupported` | The `else` belongs to the *second* `if`. Calling `getSupported("MEP")` therefore also runs the `else` branch, which does `out[0] = "Look out! Bugs!"` (line 7385) and silently clobbers the first MEP in the sorted list. |
| 4 | ⚠ `Blackberry.go:22` | `fmt.Sprintf("%02X", strIMEI)` — `%X` on a *string* is "base 16, two characters per byte" (Go `fmt` docs), so the IMEI is hex-encoded before hashing. Message becomes `33353132333435363738393132333901` instead of `35123456789123901`. Almost certainly unintended; `unlock.py` models both via `bb_message(..., go_faithful=)`. |
| 5 | `Huawei.go:18` | `fmt.Println(pre2UCSalt + " && " + pre2FCSalt)` — leftover debug output printed on every run. |
| 6 | `Alcatel.go` | `doswap` is filled for `i < len(perm)-1`, i.e. 8 of 9 slots; `doswap[8]` stays `0` and is then used. Same off-by-one on `doxor[19]`. Behaviour is consistent, but it's accidental. |
| 7 | repo root | No `go.mod` — predates Go modules, so `go build` needs `GO111MODULE=off`. |

---

## 6. Running it

```
$ python3 unlock.py 351234567891239 C700
IMEI            : 351234567891239
ZTE v1  NCK     : 690217899017
ZTE v1  SPCK    : 522305554449
ZTE v2  NCK     : 17108754
ZTE v3  NCK     : 26735136
Huawei unlock   : 44586020
Huawei flash    : 49987941
Alcatel C700 NCK  : 574001136
Alcatel C700 SPCK : 3261320467
H220m-class     : 30619753

$ python3 unlock.py --self-test        # legacy algorithms
$ python3 samsung_att.py --self-test   # Samsung/AT&T module
$ python3 samsung_att.py --unlock S26  # AT&T process + matched models
$ python3 samsung_att.py --check 2738272959528493
modern-16: 16-digit code. Newer Samsung handsets (NCK, MCK or RGCK). ...

$ python3 samsung_nvdata.py nv_data.bin  # read a stored legacy Samsung NCK
$ python3 samsung_nvdata.py --self-test  # 27 checks
$ python3 a53_att.py                     # AT&T Galaxy A53 walkthrough
$ python3 a53_att.py --check CODE        # verify a code before typing it
$ python3 a53_att.py --self-test         # 59 checks
```

Each `--self-test` re-runs every vector in its section.

---

## Sources

- Upstream source: <https://github.com/alexanderritola/Go-Unlock-Code-Calculator>
- ZTE v1 vector: <https://ukpanukpong.wordpress.com/browsing/zte_calculator/> (quoting `tools.texby.com`)
- Huawei v1 reference: <https://hvera.wordpress.com/2010-08-09/unlock-huawei-modem/> and the E589 salt table on XDA
- Modern ZTE-family algorithm: <https://github.com/kozik47/zte-imei-unlock>
- Go `fmt` verb table: <https://pkg.go.dev/fmt>
- AT&T device selector: <https://www.att.com/device-support/selector/Samsung/>
- AT&T unlock instructions (PDF): <https://www.att.com/idpassets/support/pdf/ATTDeviceUnlockCodeInstructions.pdf>
- AT&T eligibility requirements: <https://www.att.com/legal/modal/idpassets/fragment/legal/prod/legalmodal/support/smallbusinesskms/km125/km1258553.html>
- 16-digit NCK/MCK/RGCK format: <https://www.cellunlocker.net/unlock-samsung/instructions/>
- SHA-256-chain / trim-area scheme: <https://forum.xda-developers.com/showthread.php?page=2&t=931313>
- IMEI Luhn vectors: <https://github.com/arthurdejong/python-stdnum/blob/master/stdnum/imei.py>
- Legacy Samsung code **stored**, not derived — read from `nv_data.bin` at `0x146E`: <https://github.com/fbis251/sgs4g-unlock-code-finder> (ANSI C, GPL-3.0) and <https://github.com/fbis251/Galaxy-S-Unlocker-for-PC> (D). Neither references the IMEI.
- 2026 model numbers: <https://www.androidauthority.com/samsung-galaxy-2026-3616973/>

> These algorithms are documented, public and long obsolete. Use them only on
> hardware you own and are entitled to unlock.
