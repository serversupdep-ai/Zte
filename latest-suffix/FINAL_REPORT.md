# Final report — master-password algorithm for the *latest suffix*

**Date:** 2026-10-27 · **Branch:** `arena/efe15f28-zte` · **Workspace:** `latest-suffix/`
**Method:** evidence-driven static + dynamic analysis of public GitHub file
sources (repos, issues, firmware images), clean-room reconstruction, tests.

---

## 0. Executive answer

> **One sentence:** The newest Dell lock-screen suffix documented on GitHub is
> `9ABE`, but it does **not** introduce a new offline formula — the firmware
> treats it as an EC-routed family byte and copies `EC_GENERATE(tag, 0xBE)[0:16]`
> verbatim as the master code; the last suffix with an actual host-side
> tag→password algorithm remains `E7A8` (two SHA-256-tailed candidates).

The phrase "latest suffix" is ambiguous in the public material, so this report
resolves it into three different, independently evidenced facts:

| Meaning of "latest" | Answer | Evidence / confidence |
|---|---|---|
| Latest **displayed** suffix (newest lock screen reported) | **`9ABE`** — Precision 5680, `847TJ34-9ABE`, BIOS 1.29.0 (2026-06-18), posted 2026-10-13 | `bacher09/pwgen-for-bios#333`; #324 (Latitude 5440 1.30.3), #330 (Latitude 3450 1.22.1), #331 calls 9ABE "Dell's newest unlock suffix (2024+ BIOS)" — **proven** sighting, **probable** generalization |
| Latest **suffix word in the newest host-side descriptor table** | **`8FC8`**, with `params = NULL` | `Zte/bios-analysis/CF1B_FINDINGS.md §17` (Gen-C modules, 2024 Meteor Lake: table = `{0x8FC8, 0xFFFF}`), **independently re-extracted here** at file offset `0x8810` of a GitHub-sourced Latitude 5440 BIOS 1.28.1 vault module — **proven** |
| Latest **working offline formula** | **`E7A8`** — MD5-shaped mixer + SHA-256 tail, two candidate codes | `bacher09/pwgen-for-bios` `encode.ts:403-497`; `serversupdep-ai/Bin-file` `dell_e7a8_pure.py` 20/20 real vectors; extracted params at `0x8178` byte-identical to upstream — **proven** |

Unconfirmed display words (`8FCA`, `8FDC8`, `AE60`, `A6E0`, `0001`, `8FCE`)
are reported in forums/commercial lists but appear in **no** firmware suffix
table we examined — **assumed** (OCR variants / state words), never an
algorithm.

---

## 1. Scope definition

**Target (hybrid application).** Not one binary, but the Dell BIOS
master-password subsystem as visible from public GitHub file sources:

1. **Open-source keygen applications** — `bacher09/pwgen-for-bios`
   (TypeScript web app, 1.4k stars), its 2026 derivatives
   `secaicandido/bioskey` (CLI, Node 22) and
   `LeRELIKT/BIOS-Generator-Patch` (offline browser app), plus
   `chromebreakerdev/DellBIOSTools` (Python/Tk GUI + SPI patcher).
2. **UEFI SMM firmware modules** inside Dell update images —
   `DellSecurityVaultSmm` (FFS GUID `C7CAF1C7-2D97-45CB-99D9-D89AAF8ACC11`),
   `HddPwSmm`, `SystemPwSmm`, `DellNvmePwSmm`, `DellEcIoSmm/Dxe`, and the
   Microchip MEC embedded controller behind the `DellEcIo` protocol.

**Feature.** The user action is: *type a 16-character master candidate at the
BIOS admin-password prompt (often Ctrl+Enter)*. Upstream of that, a tool or the
firmware must turn the lock-screen code `XXXXXXX-SUFFIX` into that candidate.
We traced that transformation from the UI/CLI entry to the produced bytes, for
legacy, E7A8 and the newest EC-era suffixes.

**What "reconstructing it" means here.**
(a) build a source-anchored suffix catalogue with dates and confidence;
(b) implement the last local algorithm (E7A8) from scratch;
(c) implement the *actual* latest-suffix host-side algorithm (EC session
framing + response→code render), including the 8FC8 variant;
(d) prove equivalence with the originals using public vectors and a real
firmware module, and explicitly disprove the newest GitHub claim that a new
offline formula exists.

**Authorization.** Only public GitHub files, public firmware update images and
public issue threads were read. No live machine, no Dell backend, no paid
oracle, no private data. All tooling is for hardware the reader owns or is
authorized to service; repeated wrong codes can cause a lockout.

---

## 2. Setup and preparation

**REA MCP / binary-analysis IDEs.** The prompt suggests `npx rea-agents setup`
and Hopper/Ghidra/IDA. Neither the REA MCP server nor those GUIs are available
in this sandbox, and no live locked machine is attached. I therefore used the
equivalent evidence-driven toolchain that *is* reachable:

| Step | Tool actually used | Source |
|---|---|---|
| Source acquisition | `git clone` (depth 50+) + GitHub REST API `/repos/.../issues/comments` | github.com, codeload.github.com, api.github.com |
| Run upstream app | Node 22.22.3 (`--experimental-strip-types`), `npm install jsbi` | registry.npmjs.org |
| Firmware acquisition | `BIOS_IMG.rcv.part1/part2` from `serversupdep-ai/Bin-file` (committed 2026-09-07) | github.com |
| Unpack Dell PFS | `DellPfsExtract` class from `chromebreakerdev/DellBIOSTools/vendor/biosutilities/dell_pfs_extract.py` | github.com |
| Walk FFS/LZMA | `uefi_firmware.AutoParser` (pypi) + `serversupdep-ai/Bin-file/tools/dell_newbios_probe.py` | pypi.org / files.pythonhosted.org |
| Carve vault PE | `serversupdep-ai/Bin-file/tools/dell_vault_grab.py` | github.com |
| Independent PE table extraction | our `vault_inspect.py` (stdlib `struct`) | this workspace |
| CPU emulation evidence | prior in-repo Unicorn runs (`bios-analysis/dell_cf1b_session_emu.py`, `CF1B_FINDINGS.md §11`) + `bacher09`'s March 2026 Unicorn/Qiling examples | github.com / this repo |

Every repo/commit/blob SHA and issue permalink is pinned in
`evidence/github_sources.json`; hashes of the firmware files are in
`evidence/firmware_5440_1281.json`.

---

## 3. Surface mapping

### 3.1 Application surface (pinned commits, file:line)

| Module | File:function:line | Role |
|---|---|---|
| `secaicandido/bioskey@f544e1e` | `src/cli.ts:22` `keygen(raw)` | CLI entry, prints "experimental" warning for modern suffixes |
| | `src/index.ts:48` `keygen()` | runs every solver |
| | `src/dell/index.ts:243` `dellSolver` | validates 11-char `TAG+SUFFIX`, slices `serial[0:7]`, `suffix[7:11]` |
| | `src/dell/index.ts:135` `keygenDell()` | builds `fullSerial = serial + tag`; chooses SHA vs MD5 path |
| | `src/dell/index.ts:163` `calculateE7A8()` | `Sha256(intArrayToByte(encoder.encode(block)))`, then `table[(h[i+16]+h[i]) % 72]` |
| | `src/dell/index.ts:194` `isSha256DellTag` | **the 2026 extension**: E7A8 + `3FE2/8FC8/CF1B/9ABE/1B58` |
| | `src/dell/types.ts:30` `SHA256_DELL_TAGS`, `:39` `MODERN_DELL_TAGS` | suffix lists |
| | `src/dell/encode.ts:403` `TagE7A8Encoder`, `:484` `TagE7A8EncoderSecond`, `:510-515` encoder map | MD5-shaped mixer, both code variants |
| | `src/cryptoUtils.ts:147` `Sha256` | SHA-256 primitive |
| `bacher09/pwgen-for-bios@5d2caca` | `src/keygen/dell/encode.ts:406-413` `loopParams=[17,13,12,8]`, `encodeParams[]`; `:497` second encoder `[17,13,12,16]` | upstream ground truth |
| | `src/keygen/dell/index.ts:134-203` | legacy + E7A8 dispatch |
| `chromebreakerdev/DellBIOSTools@869a79f` | `DellBiosTools.pyw:1373` `common_tags` = 595B…E7A8; `:1416` "For 8FC8 suffixes, use the 'BIOS Unlocker' tool instead" | GUI: legacy generator only, new suffixes → SPI patcher |
| | `:934` `calculateE7A8`, `:948` `keygenDell` | Python port of the same engine |
| `LeRELIKT/BIOS-Generator-Patch@89e1308` | `app.js:5` `suffixes=['595B','2A7B',...,'E7A8']` | published **2026-10-25**, still legacy-only + 8FC8 patcher |
| `serversupdep-ai/Bin-file@73acbc1` | `analysis/REPORT.md §6c/6d`, `analysis/9ABE_PAIR_HUNT.md §5`, `tools/dell_e7a8_pure.py`, `tools/dell_newbios_probe.py:17,95`, `tools/dell_vault_grab.py:175` | E7A8 RE + suffix catalogue + 9ABE intake pipeline |
| `serversupdep-ai/Zte@e868fc1` | `bios-analysis/CF1B_FINDINGS.md §11,§17`, `dell_cf1b_session_emu.py`, `solution_kit/src/dell_ec_keygen.py`, `solution_kit/src/dell_latest_keygen.py`, `dell-keygen/vectors.json` | EC protocol reversal + Gen-C "8FC8-only" table + 72 vectors |

### 3.2 Firmware surface (new extraction, Latitude 5440 BIOS 1.28.1)

```
BIOS_IMG.rcv.part1 + part2                (28,065,736 B, sha256 489a8906…)
  └─ Dell PFS: "1 BIOS_IMG_candidate -- 1 System BIOS with BiosGuard v1.28.1.bin"
       (25,165,824 B, sha256 7b2c7d79…; model info: Latitude 5440 / 1.28.1)
       └─ FFS C7CAF1C7-2D97-45CB-99D9-D89AAF8ACC11  (UI: DellSecurityVaultSmm)
            └─ section1.pe 38,912 B  sha256 308bfefc72690c51dd7b8792cf95213172dc168032d40915951f8e23ce5e6616
                 .text  VA 0x1000 raw 0x0400 size 0x7C00
                 .data  VA 0x9000 raw 0x8000 size 0x0E00   (VA→file delta -0x1000)
```

Strings / words found in `.data` (all offsets are file offsets):

| Offset | Content | Meaning |
|---|---|---|
| `0x8130` | 72-char `0Q2drGk99WLJ1EGnqR5y3DGr16hN4seZPRM2zz2pzcU7JaBXIjbkGZrkQFMxN[Z638myIL2r` | 8FC8 render alphabet (VA `0x9130`) |
| `0x8178` | `50501010 0a010908 00a08097 60606161 60606161 000a0008 00100097 50501010` + `11 0d 0c 08` | E7A8 `encodeParams` + `loopParams=[17,13,12,8]` (VA `0x9178`) |
| `0x81b0` | 72-char `Q92G0drk9y63r5DG1hLqJGW1EnRk[QxrFMNZ328I6myLr4MsPNeZR2z72czpzUJBGXbaIjkZ` | E7A8 output alphabet (VA `0x91B0`) |
| `0x81f8` | `1B58 9ABE 3FE2 CF1B 8FC8 FFFF` | **EC-routed family list** (VA `0x91F8`) |
| `0x87c0` | another 72-char permutation | legacy BF97/T72 output alphabet |
| `0x8810` | 24-byte descriptor `8FC8 / params=0 / alpha=0x9130` | 8FC8 has **no local encoder** |
| `0x8828` | 24-byte descriptor `E7A8 / params=0x9178 / alpha=0x91B0` | last local algorithm |
| `0x8840` | `FFFF` | table terminator |

`HddPwSmm` carries the same family list at file `0x5210` (preceded by
`0001 FFFF`). `SystemPwSmm`, `DellEcIoSmm`, `DellEcIoDxe` carry no new-suffix
words. No `9ABE`, `CF1B`, `3FE2` or `1B58` descriptor entry exists in any of
the three vault modules extracted by `dell_vault_grab.py`.

**False positive found and ruled out.** A naive 16-bit context dump around
`0x81f8` reads `6A49 5A6B 1B58 9ABE 3FE2 CF1B 8FC8 FFFF`. `0x6A49`/`0x5A6B`
are the ASCII bytes `I j` / `k Z` — the last four characters of the E7A8
alphabet (`…JXGabIjkZ`). They are **not** new suffixes; `dell_newbios_probe.py`
prints them only because it dumps three words of context before the first known
word. Our `vault_inspect.py` therefore requires contiguous *known* family words.

**Other image families / cross-references (do not mix VAs across images).**

* Latitude 5330 (2022, from issue #80 comment `5067918343`): `DellSecurityVaultSm`
  suffix dispatch table VA `0x9760` = `[8FC8 encoder=0x0, alpha=0x91A0;
  E7A8 encoder=0x91E8, alpha=0x9220]`; keygen gate `0x553C`; compute `0x58B4`;
  suffix lookup `0x45E8`; SHA-256 `0x8278`; `CopyMem 0x81F4`,
  `CompareMem 0x11E0`, `ZeroMem 0x11C0`; verify `0x68D4`→`0x6910`.
* OptiPlex 3090 BIOS 2.27.0 (`Zte/CF1B_FINDINGS.md §11`): EC family list
  `0xA3C8`; GUID map `0x30E8`; EC session `0x37AC`; `is_ec_routed_family`
  `0x9580`; dispatch lookup `0x8060`, table `0xa9e0`; render `0x8E18`,
  alphabet `0xa280`; DellEcIo interface global `0xafc0`; cmd `0x17`;
  ports `0x910/0x911`, window `0x10–0x1F`.

**IPC / protocol surface.** `DellEcIo` protocol GUID
`7310E28E-96EA-4360-946E-5ADC6BE8F531` (issue #80 comment `4010168130`);
type-6 `GENERATE` descriptor GUID `{C065AEAB-…}`; mailbox session
`{21 00 03 06}` (cmd `0x21`, sub `3`, type `6`).  There is **no network call**
in the target feature: all traffic is host↔EC port I/O.  The only network in
this research was fetching GitHub/API/PyPI/npm sources; paid "8FC8/CF1B/9ABE
unlock" services are out-of-band oracles, not part of the algorithm.

---

## 4. Feature tracing — complete call chains

### 4.1 Application chain (what an open-source keygen actually does)

```
user: "CX8F9C3-3FE2"                                      [lock-screen code]
  → src/cli.ts:22          keygen(raw)                    (strip spaces; print experimental warning)
  → src/index.ts:48        keygen()                      (iterate solvers)
  → src/dell/index.ts:243  dellSolver.fun()              (len==11, suffix ∈ DellTag)
  → src/dell/index.ts:135  keygenDell(serial, tag, ServiceTag)
       fullSerial = serial + tag                         # e.g. "CX8F9C33FE2"
       bytes → 16 LE u32 words (zero-padded)
  → src/dell/types.ts:51   isSha256DellTag(tag)           # TRUE for E7A8 **and** 3FE2/8FC8/CF1B/9ABE/1B58 in bioskey
  → src/dell/index.ts:163  calculateE7A8(block, TagE7A8Encoder)        → code 1
                            calculateE7A8(block, TagE7A8EncoderSecond)  → code 2
  → src/dell/encode.ts:403 TagE7A8Encoder.makeEncode()    (64 rounds, 17+13 outer loops)
  → src/cryptoUtils.ts:147 Sha256.digest()                (SHA-256 of the 16-byte state)
  → src/dell/index.ts:169  out[i] = alphabet[(h[i+16]+h[i]) % 72]
  → CLI: two 16-char candidates
```

For legacy suffixes the same `keygenDell()` instead runs `calculateSuffix()` +
`blockEncode()` + `resultToString()` (MD5-family path); for `A95B` it aliases
`595B`.  `DellBIOSTools.pyw:948` is the same structure in Python.

**Critical observation (the 2026 claim).** `bioskey` adds five suffixes to
`DellTag` and maps them to `TagE7A8Encoder` (`encode.ts:510-515`). It changes
**only the 4 characters appended to the hashed serial**. Its own
`docs/ARCHITECTURE.md` says: *"Extension added here. Not an upstream vector …
Treat the two printed strings as candidates."* It is a hypothesis, not RE.

### 4.2 Firmware chain for the latest suffix (9ABE / EC era)

```
user enters 16-char candidate at BIOS password prompt
  → SMM verify routine (Latitude 5330: 0x68D4 → 0x6910; 3090: fn 0x3314)
  → read machine's suffix word (u16) from NVRAM config
  → suffix lookup / family classification
       Latitude 5330: lookup 0x45E8 → descriptor table 0x9760
          8FC8 → encoder_ptr = 0x0 → keygen 0x553C returns EFI_INVALID_PARAMETER
          E7A8 → encoder_ptr = 0x91E8 → compute 0x58B4 → SHA-256 0x8278 → compare
       3090 2.27.0: is_ec_routed_family 0x9580 tests list @0xA3C8
          {1B58, 9ABE, 3FE2, CF1B, 8FC8} → yes → EC path
  → EC path (DellEcIoSmm, GUID 7310E28E-…, ports 0x910/0x911, cmd 0x17)
       fn 0x37AC: type-6 {C065AEAB} GENERATE
       wire: open {21 00 03 06}; send service tag (7 B); send family LSB
             (9ABE→0xBE, CF1B→0x1B, 3FE2→0xE2, 1B58→0x58, 8FC8→0xC8)
             recv 32 bytes; recv 1 status byte (0 = OK)
  → fn 0x8E18 response→code render (all three branches byte-verified by emulation)
       CF1B / 3FE2 / 1B58 / 9ABE: out = resp32[0:16] VERBATIM
                                  code2 = resp32[16:32]
       8FC8: out[i] = alphabet0[(resp32[i]+resp32[i+16]) % 72]   (alphabet @0xa280 / 0x91A0 / 0x8130)
       E7A8: legacy local tail (not EC-routed)
  → compare (some generations hash the response again before compare — issue #80
    comments 5935232074 / 6032854612) → PASS/FAIL
```

The EC-internal `tag → resp32` transform is **not** in the host firmware: the
8FC8 descriptor's encoder pointer is NULL from its introduction (2019 Latitude
7400 1.2.0 and 2022 Latitude 5330 — issue #80 comment `5067918343`), and 9ABE
never gets a descriptor at all (our 1.28.1 extraction).  Earlier in-repo work
(`CF1B_FINDINGS.md §11.7`) proves the EC payloads are AES-sealed with per-image
keys; no public offline keygen exists.

### 4.3 Our GitHub-files → tables chain (reproducible)

```
git clone serversupdep-ai/Bin-file@73acbc1
cat BIOS_IMG.rcv.part1 BIOS_IMG.rcv.part2 > BIOS_IMG.rcv
DellPfsExtract(BIOS_IMG.rcv)                        → System BIOS v1.28.1 (Latitude 5440)
uefi_firmware.AutoParser(...).dump()                → FFS C7CAF1C7-…/section1.pe
python3 vault_inspect.py evidence/…pe                → descriptor tables + family lists
                                                       + alphabets + params (stdlib only)
```

---

## 5. Evidence collection

### 5.1 Key pseudocode (recovered, not copied)

```text
# Local keygen descriptor (24 B/entry, 0xFFFF-terminated)
struct Desc { u16 suffix; u16 pad; u32 pad; u64 params_va; u64 alphabet_va; }
Latitude5440_1.28.1 @file 0x8810:
  { 8FC8, params = NULL, alphabet = 0x9130 }
  { E7A8, params = 0x9178, alphabet = 0x91B0 }
  { FFFF }
EC-routed family list @file 0x81F8: [1B58, 9ABE, 3FE2, CF1B, 8FC8, FFFF]

# E7A8 (last local algorithm)
block  = LE32( tag + "E7A8" , zero-padded to 16 words )
state  = MD5_shaped_mixer(block, md5magic2, encodeParams, loops=[17,13,12,8])
h      = SHA256( bytes(state) )
code1  = alphabet[ (h[i+16] + h[i]) % 72 ]  for i in 0..15
code2  = same with extended K-table and loops=[17,13,12,16]

# Latest suffix (EC era)
resp32 = EC_GENERATE(tag, family_lsb)                 # sealed EC transform
9ABE/CF1B/3FE2/1B58: master = resp32[0:16]
8FC8:                 master[i] = alphabet[(resp32[i]+resp32[i+16]) % 72]
```

### 5.2 Claim → evidence → confidence

| # | Claim | Evidence | Confidence |
|---|---|---|---|
| 1 | `9ABE` is the newest displayed suffix on GitHub (2026-10-27) | issues #333 (2026-10-13, Precision 5680 BIOS 1.29.0), #331, #324, #330; `Bin-file/REPORT.md §6c` ("9ABE 2025–2026 newest gen") | **proven** (sighting); probable (global "newest") |
| 2 | A real 5440-class BIOS image is available in GitHub files | `Bin-file` `BIOS_IMG.rcv.part1/2` (commit `858d6d7`, 2026-09-07), PFS model info = Latitude 5440 / 1.28.1; hashes in `firmware_5440_1281.json` | **proven** |
| 3 | The newest image gives 8FC8 a NULL encoder and no 9ABE descriptor | our extraction `0x8810` (params=0) + `0x81F8` family list; independent `dell_newbios_probe.py` + `dell_vault_grab.py` runs; issue #80 `0x9760`/`0x553C` | **proven** |
| 4 | E7A8 params/alphabet in that image equal upstream open-source constants byte-for-byte | `0x8178` = `50501010 0a010908 …` + `[17,13,12,8]`; `0x81b0` alphabet; vs `encode.ts:406-413`, `dell_e7a8_pure.py` | **proven** |
| 5 | `master(tag,9ABE) = resp32[0:16]` | `Zte/CF1B_FINDINGS.md §11.3` emulation (all 4 verbatim families); issue #80 comments `4976691066`, `5935232074`, `6032854612`; `solution_kit/src/dell_ec_keygen.py` | **proven** (emulation) / **probable** on untested 2026 EC builds |
| 6 | `8FC8` render uses the 72-char alphabet with a half-sum | emulation vector `ABCDEFGHIJKLMNOPQRSTUVWXYZ012345` → `2rk9L1Gq53kZkFx[`; alphabet extracted at `0x8130` equals issue #80 `0x91A0` table | **proven** |
| 7 | `bioskey`'s "new suffix support" is just E7A8 with the displayed suffix in the serial | `src/dell/types.ts:30`, `encode.ts:510-515`, `index.ts:194`; its own `docs/ARCHITECTURE.md`; our reconstruction reproduces all 13 observed Node outputs exactly | **proven** |
| 8 | That hypothesis is not the 8FC8 algorithm | 4/4 public 8FC8 field pairs (`BZsa9RGZzyIGD3pI`, `2QqPqMGQxLNrrZxW`, `kr8a9e2xdPGRb1Lz`, `N9NM9j1qRMeGzyyr`) do not match its outputs; issue #80's 1,755-configuration search also failed; firmware encoder is NULL | **proven** for 8FC8; **unfalsified but unsupported** for 9ABE (zero public 9ABE pairs) |
| 9 | `8FCA/AE60/A6E0/8FDC8` are not firmware suffix families | `Bin-file/9ABE_PAIR_HUNT.md §5`; absent from every extracted `.data` table; commercial/Reddit listings only | **assumed** (probably OCR/state variants) |
| 10 | `8FC8` is "the latest suffix" in `dell_latest_keygen.py` | `CF1B_FINDINGS.md §17`: newest Gen-C modules carry a one-word table `{0x8FC8, 0xFFFF}` | **proven** — but it means *latest host-side table word*, not latest displayed suffix; see §0 |
| 11 | EC firmware holds a secret transform (no offline keygen) | issue #80 comments `4003614643`, `4010168130`, `4010522711` (DellEcIo GUID, EC firmware encrypted, MEC172x); `CF1B_FINDINGS.md §11.7` | **probable** (multiple independent static analyses; not directly executed here) |

### 5.3 Data formats, storage and network

* **Screen code:** 7 alphanumeric service tag + 4 hex chars (`XXXXXXX-9ABE`);
  hyphen optional; some reports show 5-char OCR variants (`8FDC8`). Suffix is
  a little-endian `u16` family word in NVRAM config.
* **Local keygen input:** `(tag + suffix)` ASCII → 16 zero-padded LE `u32`
  words; state = 4×`u32`; SHA-256 over 16 bytes; output = 16 chars from a
  72-char alphabet.
* **Descriptor table:** 24 B/entry — `u16 suffix`, `u16 pad`, `u32 pad`,
  `u64 params_va`, `u64 alphabet_va`; `0xFFFF` terminator. `params_va == 0`
  disables local derivation.
* **EC wire:** cmd `0x21`, sub `3`, type `6`; 7 B tag; 1 B family LSB;
  32 B response; 1 B status. Transport: ports `0x910`/`0x911`, selector doorbell,
  window `0x10–0x1F`, cmd-`0x17` packets. Response halves give code 1 / code 2
  for verbatim families.
* **Storage:** enrolled password state in SPI flash / SIVB vault / EC internal
  NVRAM (record `0x15` is the enrolled master on older ECs). No plaintext
  password comparison in the SMM modules; comparisons are over computed digests.
* **Network:** none in the feature. Dell's backend / paid per-machine services
  are external oracles, not reachable from the firmware path we traced.

### 5.4 Observed edge cases and error handling

1. **8FC8 code 2 == code 1** — the half-sum is commutative; the published
   `render_second()` is diagnostically identical. Documented and tested.
2. **NULL encoder** → `EFI_INVALID_PARAMETER` (`0x8000000000000002`) in the
   5330 keygen `0x553C`; no code is produced.
3. **E7A8 parameter rotation** on some late-2024+ BIOS branches
   (`Bin-file/REPORT.md §6c`): public params fail on Latitude E7270/E7470/3190;
   our reconstruction is honest about branch-specific params. The 5440 1.28.1
   image we extracted uses the *unrotated* published params.
4. **`0001`** is a lockout-state word (legacy canonicalisation), not a key
   family. **`8FCE`** does not exist (OCR of 8FC8).
5. **6A49/5A6B** are alphabet bytes, not suffixes (§3.2).
6. **Short/odd EC response** → our renderer raises `ValueError`; non-ASCII
   verbatim bytes are preserved via Latin-1 (no silent ASCII cleanup).
7. **Keyboard entry** is US-QWERTY, case-sensitive, often Ctrl+Enter; `[` is a
   legitimate output character. Repeated wrong entries can lock the firmware.
8. **No "tag mismatch" status** exists in the EC status vocabulary
   (`CF1B_FINDINGS.md §11.22.3`); the "donor machine can mint any tag's code"
   idea is a *hypothesis*, not proven. A captured response should therefore be
   treated as valid only for the target machine or an identical EC build.

---

## 6. Reconstruction

`latest_suffix.py` is original, stdlib-only Python (no upstream source copied):

* **`SuffixSpec`/`CATALOG`** — 22 suffixes with mechanism, generation,
  confidence, family byte and evidence URLs. `resolve()` returns a structured
  verdict: local codes when they exist, otherwise the exact EC input needed
  (family byte, wire sequence, reference tool), never a fabricated password.
* **`MixingEngine` + `e7a8_codes()`** — clean re-expression of the arithmetic
  specification (round functions, 64-word K-table, rotations, two loop sets,
  SHA-256 tail). Numeric tables are facts (§3.2), not copied code.
* **`render_ec_response()`** — the real latest-suffix host-side algorithm for
  all five EC families, including the 8FC8 alphabet map.
* **`hypothesis_codes()`** — an *explicitly labelled* reproduction of
  `bioskey`'s guess, used only as a negative control.
* **CLI** — `TAG-SUFFIX`, optional `--resp <64 hex>`, `--hypothesis`,
  `--catalog`, `--json`.
* **`vault_inspect.py`** — stdlib PE parser that re-derives descriptor tables,
  EC family lists, alphabets and E7A8 params from the committed firmware module.

**Documented assumptions.** (i) the 5440 1.28.1 image represents the 9ABE
generation (same model/BIOS line as #324/#333; the image does not record the
lock-screen suffix — marked *probable*); (ii) the EC render map from the 3090
2.27.0 emulation generalizes to 2026 EC builds (supported by the identical
`GENERATE` markers in the 5440 1.31.1 image per PR #2, but not field-validated
on 9ABE — issue `Zte#3` was inconclusive); (iii) unconfirmed display words are
*not* algorithm families until a firmware table says otherwise.

---

## 7. Verification

```
$ cd latest-suffix && python3 -m unittest -v test_latest_suffix.py
Ran 36 tests in 0.19s — OK

$ python3 verify_sources.py
29 OK / 0 SKIP / 0 FAIL   (every pinned GitHub commit + blob SHA resolves)
```

| Group | What is compared | Result |
|---|---|---|
| E7A8 vs `Bin-file` real-world vectors | 10 tags × 2 codes | **20/20** |
| E7A8 vs in-repo `dell-keygen/vectors.json` | 6 tags × 2 codes | **12/12** |
| E7A8 vs issue #80 field codes (bacher09, 2021) | 3 first codes + 2 full second codes | **5/5** (third second-code quote is a truncated prefix, matched as prefix) |
| E7A8 vs `bioskey` JS test vector | `1234567-E7A8` | **2/2** |
| Reconstruction of `bioskey` hypothesis | 13 observed Node 22 outputs (8FC8/9ABE/3FE2/CF1B/1B58/E7A8) | **26/26** byte-exact |
| Negative control | 4 public 8FC8 field pairs vs hypothesis outputs | **4/4 mismatches** (hypothesis rejected) |
| EC render vs firmware emulation | 5 families on canned 32-byte response | **10/10** |
| Firmware re-extraction | PE hash, family list, NULL 8FC8 encoder, E7A8 params, both alphabets, `6A49` false positive | **all pass** |
| CLI / catalogue / parse edge cases | 3 CLI runs + 10 dispatch/parse tests | **all pass** |
| Source integrity | `verify_sources.py` re-resolves all pinned commit/blob SHAs at api.github.com | **29/29 OK** |

**Iteration notes.** (1) The 8FC8 "second candidate" initially looked like a
bug; tracing `fn 0x8E18` showed addition is commutative, so equality is
correct — now a test. (2) The `6A49 5A6B` words initially looked like two brand
new suffix families; byte inspection showed they are alphabet tail ASCII —
`vault_inspect.py` now filters by known words. (3) The apparent conflict
between "9ABE is newest" (GitHub issues) and "8FC8 is latest" (repo §17) was
resolved as two different meanings of *latest*, both now in the catalogue.
(4) `bioskey`'s own tests pass (6/6) but only test self-consistency, not real
machines; our field-pair negative controls supply the missing comparison.

---

## 8. Final assessment

**What has been proven.** The suffix→mechanism map for every family seen on
GitHub through 2026-10-27; that the newest displayed suffix `9ABE` is EC-routed
with a verbatim response render; that `8FC8` is the newest host-side table word
with a NULL encoder; that `E7A8` is the last offline formula and its constants
are unchanged in a 2026-class 5440 image; and that the newest GitHub repo
claiming new-suffix support (`secaicandido/bioskey`, 2026-10-18) is an
unvalidated E7A8 variant that fails every public 8FC8 field pair.

**What remains unknown.**
* The EC-internal `tag → resp32` transform (sealed firmware / per-image keys);
  therefore no offline keygen for 9ABE/8FC8/CF1B/3FE2/1B58.
* Whether `bioskey`'s guess works on *any* 9ABE machine — zero public 9ABE
  (tag → code) pairs exist, so it is unfalsified but unsupported and
  contradicts the firmware architecture.
* The exact displayed suffix of the 1.28.1 image; E7A8 rotated params for
  other BIOS branches; the meaning of `8FCA`/`AE60`/`A6E0`.
* The "RSA signed challenge" model in issue #80 is explicitly a hypothesis,
  not proven end-to-end; we did not rely on it.
* Field validation of the EC readout on a locked-but-bootable 9ABE machine
  (`Zte#3`) is still inconclusive.

**Practical route for a real `XXXXXXX-9ABE` machine.** There is no free offline
master-password generator. In order: (1) ask the machine's own EC —
`bios-analysis/solution_kit/src/dell_ec_keygen.py --keygen/--render` or
`bios-analysis/dell_cf1b_master.c` (family byte `0xBE`, ports `0x910/0x911`,
root, bare metal); (2) Dell support with proof of ownership; (3) SPI dump patch
(`bios-analysis/dell_unlock_image.py`). Legacy/E7A8 machines can use
`dell-keygen/keygen.html`, which remains 72/72-validated.

**Reproduce everything.**

```bash
cd latest-suffix
python3 -m unittest -v test_latest_suffix.py
python3 vault_inspect.py --json | head -40
python3 latest_suffix.py --catalog
python3 latest_suffix.py 847TJ34-9ABE --hypothesis
python3 latest_suffix.py 7QJ4H42-E7A8
```

Pinned sources: `evidence/github_sources.json` (repos, commits, blob SHAs,
issue/comment permalinks), `evidence/firmware_5440_1281.json` (image hashes and
extraction chain), `evidence/vectors.json` (all comparison data).
