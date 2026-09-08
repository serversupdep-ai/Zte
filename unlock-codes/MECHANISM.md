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

## 4. Bugs in the upstream Go repo

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

## 5. Running it

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

$ python3 unlock.py --self-test
...
0 failure(s)
```

`--self-test` re-runs every vector in section 2.

---

## Sources

- Upstream source: <https://github.com/alexanderritola/Go-Unlock-Code-Calculator>
- ZTE v1 vector: <https://ukpanukpong.wordpress.com/browsing/zte_calculator/> (quoting `tools.texby.com`)
- Huawei v1 reference: <https://hvera.wordpress.com/2010-08-09/unlock-huawei-modem/> and the E589 salt table on XDA
- Modern ZTE-family algorithm: <https://github.com/kozik47/zte-imei-unlock>
- Go `fmt` verb table: <https://pkg.go.dev/fmt>

> These algorithms are documented, public and long obsolete. Use them only on
> hardware you own and are entitled to unlock.
