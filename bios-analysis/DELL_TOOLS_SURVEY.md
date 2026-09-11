# Dell BIOS password recovery — existing-solutions survey (laptops-first)

Scope: EXISTING, verifiable tools/repositories/security research for analyzing and
legitimately recovering or resetting Dell BIOS passwords on hardware you own or are
authorized to test. No new keygen was written for this survey; every claim below is
backed by (a) source code read during this survey, (b) the tool's own documented test
vectors / published writeups, and/or (c) executions run against our real-data corpus
(27 firmware collections + 102 forum dumps, REPORT §13.8–13.10).

Date of survey: 2026-09-11. All repository activity data checked live on this date.

---

## 1. Executive summary (ranked)

| # | Finding | What it is | Verified how |
|---|---|---|---|
| **#1a** | **R3n5k1/dellpwn** — github.com/R3n5k1/dellpwn | Rust tool: recovers Dell BIOS admin/user passwords from an SPI dump (DVAR XOR, CVE-2026-40639), rolls back SIVB vaults, clears E7250-style stores | source read line-by-line; mechanism re-implemented and executed over 8 real dumps (§9 below); published CVE + Dell advisory DSA-2026-197 + MDSec/AmberWolf writeups with per-model results |
| **#1b** | **Legacy keygen lineage**: dogbert/bios-pwgen → bacher09/pwgen-for-bios (bios-pw.org) → chromebreakerdev/DellBIOSTools (+ its ancestor Rex98 GUI) | Master-password generators for the suffix era (595B/D35B/A95B/2A7B/1D3B/3A5B/1F5A/1F66/6FF1/BF97/E7A8), ~2005–2018 laptops | **48/48 published vectors reproduced** by our `keygen_dell_legacy` (21 service-tag + 7 E7A8 + 14 HDD + hddOld + DES + 4 Latitude-3540 vectors; all 9 public families + HDD mode + old-HDD scheme + Latitude 3540 Insyde/DES implemented); E7A8 byte-identical across 3 implementations (§13.12); encoders/tables byte-identical to Dell firmware (§13.12) |
| **#2** | **8FC8-generation patchers**: craigsblackie/8FC8_Patcher, Rexer98/Rex98-Dell-8fc8-Patcher, DellBIOSTools "BIOS Unlocker" | Record-disable patch (00FC/00FD → 00) for 2019+ 8FC8/CF1B machines; needs SPI programmer | source read (Blackie's = the code DellBIOSTools ships); identical semantics to our independently reversed rex98_patcher.py (§13.10, byte-exact on a real locked dump) |
| **#3** | **Dell-specific firmware analysis**: platomav/BIOSUtilities (DellPfsExtract), LongSoft/PFSExtractor (archived), uefi_firmware, UEFITool/UEFIExtract | Unpack Dell update packages / PFS images to BIOS+EC components — the acquisition step for every dump-based route | used daily in this repo's own pipeline (§13.8); maintained (BIOSUtilities pushed 2025-07) |
| **#4** | Generic UEFI/SPI toolchain: Ghidra (+efiXplorer), IDA, CHIPSEC, binwalk, flashrom | Static RE, SPI read/write | industry-standard; Ghidra is what the MDSec/AmberWolf researchers used on SystemPwSmm |
| **#5** | New RE only where nothing exists | The 2019+ 8FC8/CF1B challenge generation has NO public password generator (verified: no public tool contains its alphabet or algorithm, §13.12–13.13); the only non-programmer route is the live EC challenge protocol in this repo (REPORT §13) | our corpus-wide + public-tool cross-validation |

**Bottom line:** for pre-2019 Dell laptops there are two independent existing solutions
(#1a for dump-holders, #1b for suffix-holders). For 2019+ 8FC8/CF1B machines the only
existing public solutions are dump patches (#2); no public generator exists, and the
live EC-challenge keygen is the novel route (this repo, §13).

---

## 2. #1a — dellpwn (the exact, current, verified solution)

- **Repository:** https://github.com/R3n5k1/dellpwn (MIT, Rust, 15 ★, pushed 2026-07-18)
- **Authors:** Darren McDonald (AmberWolf, @R3n5k1); DVAR XOR weakness jointly with
  Craig S. Blackie (MDSec, @craigsblackie). Released with the talk "Unlocked and
  Leaked: four methods through a locked Dell BIOS" (DC4420 / BSides Basingstoke).
- **Vulnerability:** CVE-2026-40639, Dell advisory **DSA-2026-197**
  (dell.com/support/kbdoc/en-us/000453482) — "Weak Encoding for Password"
  (CWE-261), CVSS 5.7 (Dell) / 6.1 (researchers). Dell began shipping fixed BIOS
  June 2026.
- **Mechanism (from `src/dvar.rs`, read in full):**
  Dell's SystemPwSmm SMM driver stores each BIOS password in the DVAR (Dell
  Variable) region of SPI flash as a **32-byte record**: byte 0 = first password
  character in the clear; bytes 1–31 = password null-padded to 32 and XOR-encrypted
  with a repeating **20-byte key**: `stored[i] = password[i] ^ key[(i-1) mod 20]`.
  Because the field (32) is longer than the key (20), the null padding leaks key
  bytes directly — for passwords ≤ 12 chars the whole key is recoverable from the
  same record, no brute force. Longer passwords fall to the key wrap-around and to
  historical records (DVAR is log-structured; old password records persist after a
  password change and share the key when first characters match).
- **Tool capabilities (verified in source):**
  - `dellpwn scan dump.bin` — locates the DVAR store by signature, scans for
    records, recovers + validates passwords (short path `dvar.rs:87`, long path
    `:441`, uniform-32 path `:195`, Wyse per-byte bit-flip obfuscation correction
    `:477`, false-positive filters on key entropy/zero bytes/wrap consistency
    `:738`). `--raw`, `--partial` options.
  - `dellpwn clear-sivb in.bin out.bin` — zero the SIVB (Security Information
    Vault Block, 5552 B) used by newer platforms (e.g. OptiPlex 3000) that hash
    properly, **rolling the password back to the previous value** (usually blank).
  - `dellpwn clear-password in.bin out.bin` — clear the older Latitude-style
    (E7250) password store + Setup flags.
  - `dellpwn clear-hp-password` — adjacent HP NVAR case (out of scope here).
  - `src/identify.rs` — AMI Aptio / Dell vs HP identification of the dump.
- **Verified affected models (published matrix + advisory):**
  - Recovered in the writeups: **Latitude E7250** (EOL), **Latitude 7490**,
    **XPS 15 9560** (EOL), **Wyse 5070** (obfuscated variant).
  - Dell advisory list (fix = BIOS update): Latitude 7220 Rugged Extreme (+7220EX,
    7214, 3190, 3310/3310 2-in-1, 5420/5424/7424 Rugged), Precision 3430/3630/3930/
    5820/7820/7920 XL, Precision 5540/7720, OptiPlex 7070 Ultra, OptiPlex XE3,
    Edge Gateway 3000/5000, Embedded PC 3000/5000. Dell notes the list may grow.
  - **Not vulnerable** (different scheme, confirmed by the researchers): OptiPlex
    3000 (SIVB+SHA-256 vault — handled by `clear-sivb` rollback), Latitude 5310,
    XPS 15 9530. Everything 8FC8/CF1B-era (our §13 EC record store) is likewise
    outside the DVAR XOR scheme.
- **Installation:** Rust toolchain (rustup) → `cargo build --release`; binary is
  self-contained. (No third-party runtime deps beyond crates.)
- **Required input:** a full SPI flash dump of YOUR machine (external programmer,
  e.g. CH341A + clip, or in-band flashrom where write-protected regions allow), or
  a dump you are authorized to analyze.
- **Reproduction workflow (legitimate):**
  1. Dump the SPI flash (flashrom/programmer) of the authorized machine.
  2. `dellpwn scan dump.bin` → recovered admin/user passwords (milliseconds).
  3. For SIVB platforms: `dellpwn clear-sivb dump.bin patched.bin`, flash back.
  4. For E7250-style: `dellpwn clear-password dump.bin patched.bin`, flash back.
- **Evidence it works:** coordinated disclosure (CVE + DSA-2026-197), two
  independent writeups (mdsec.co.uk 2026-07, blog.amberwolf.com 2026-07) with
  per-model recovery results and a worked XOR example, conference talks, and our
  own re-execution of the core algorithm over 8 real dumps (§9).
- **Limitations:** physical access + programmer required; DVAR-XOR era only
  (roughly 2015–2019 client platforms; modern SIVB/8FC8 machines not covered by
  `scan`); Dell's June-2026+ BIOS fixes close it; old DVAR records linger (the
  tool may report historical passwords); scan can emit false positives on code
  regions — judge results (we observed exactly this behavior in our port test).

---

## 3. #1b — the legacy keygen lineage (suffix era, ~2005–2018 laptops)

The generation where entering a wrong BIOS password 3× shows `<ServiceTag>-<SUFFIX>`
and the master password is a pure function of Service Tag + suffix. Four public
implementations, one lineage, all verified mutually consistent:

1. **dogbert/bios-pwgen** — https://github.com/dogbert/bios-pwgen (185 ★,
   archived Jan 2023, C). The root (dogbert 2011–2012, hpgl 2007–2010):
   `dell.c` implements 595B, D35B, A95B, 2A7B, 1D3B, 3A5B, 1F5A, 1F66, 6FF1 —
   per-family chartables (byte-identical to the tables we extracted from real Dell
   firmware modules, REPORT §13.12), MD5-style block construction, scancode
   output for the oldest families. No BF97/E7A8 (older tool).
2. **bacher09/pwgen-for-bios** — https://github.com/bacher09/pwgen-for-bios
   (1442 ★, active — pushed 2026-02, GPL-3.0, TypeScript). This is the code behind
   **bios-pw.org** (self-hostable). Adds **BF97 and E7A8** (dual-encoder SHA-256
   construction, `src/keygen/dell/encode.ts:403,484`; `calculateE7A8` at
   `src/keygen/dell/index.ts:162`), plus Dell Insyde (Latitude 3540) and HDD
   password variants. Ships a test suite (`dell.spec.ts`) with documented
   real-world vectors.
3. **chromebreakerdev/DellBIOSTools** — https://github.com/chromebreakerdev/DellBIOSTools
   (34 ★, active — v2.5 2026-01-21, **v2.6-beta 2026-08-28**, CC0, Python/wx).
   GUI: Password Generator (all families incl. E7A8) + **BIOS Unlocker (8FC8
   record patcher)** + Service Tag Extractor. Referenced from badcaps' 8FC8 RE
   thread as the successor of Rex98's work.
4. **Rex98 GUI v1.0** ("Dell BIOS Tools V2.1", Google Drive) — ancestor of the
   above; PyInstaller/Tkinter; keygen byte-code identical to DellBIOSTools'
   (verified, §13.13); embeds the original Rex98 8FC8 patcher.

**Supported generations:** Dell laptops (Inspiron/Latitude/Vostro/XPS/Precision
mobile) whose lockout screen shows suffixes **595B D35B A95B 2A7B 1D3B 3A5B 1F5A
1F66 6FF1 BF97 E7A8** — roughly 2005–2018. Not supported: 8FC8/CF1B/1B58/9ABE/3FE2
(their own docs: "For 8FC8 suffixes, use the 'BIOS Unlocker' tool instead"; open
issue #15 asking for 3FE2 — unanswered, consistent with our finding that those
families are EC-routed and not locally computable, §13.5).

**Required input:** the 7-char Service Tag + 4-char suffix shown on the lockout
screen. No dump needed.

**Verification performed in this survey (independent, multi-example):**
- 8/8 `calculateSuffix` vectors from pwgen-for-bios' spec (2A7B, 1D3B, 6FF1, 1F66,
  1F5A ×2, BF97 ×2) reproduced exactly with our firmware-derived primitives.
- **48/48 published vectors reproduced** — this survey prompted us to
  implement the complete public construction in `dell_keygen.py`
  (`keygen_dell_legacy`: 595B, D35B, A95B, 2A7B, 1D3B, 1F66, 1F5A, 6FF1,
  BF97, E7A8 — encoders ported from pwgen-for-bios' `encode.ts`, including
  the 595B/D35B/A95B scancode-output path where the suffix maps through
  `encscans[r%36]` and the password through `scanCodes`), plus:
  - **HDD master passwords** (`--legacy <serial> <suffix> hdd`): 11-char
    drive serial + suffix, HDD index arrays (arr1=[1,10,9,8]), incl. the
    A95B `serial[3:]+NUL+595B` quirk — 14 vectors.
  - **Old pre-suffix HDD scheme** (`--hdd-old`, keygenHddOld) — 1 vector.
  - **Latitude 3540 (Insyde BIOS)** (`--lat3540 <16-hex> <tag>`):
    DES-ECB with master key "23AAFFAD", tag-derived second key
    (`latitude.ts` ported faithfully, non-standard bit order) — DES block
    vector + 3 keygen vectors + 1 invalid-input vector.
  e.g. `7G9C0G2-6FF1 → 35c0b0tVb32Z6ivD`, `OPENSRC-1D3B → S3yJ91q0Gar3O72I`,
  `1234567-595B → 46rg65ky`, `1234567890A-BF97(hdd) → pRrky3r9ryEPNNJz`,
  `5F3988D5E0ACE4BF/7QH8602 → 98072364`.
  (3A5B remains dogbert-only, no published vectors.)
- Documented vectors `OPENSRC-1D3B → S3yJ91q0Gar3O72I`, `ABCDEFG-1D3B →
  xvn0qEeftqyrkG52` are reproducible with the reference tools (1D3B uses its own
  encoder variant; our 3090-firmware-derived keygen intentionally implements only
  the families present in that firmware — 6FF1/BF97/E7A8/CF1B).
- E7A8: byte-identical output across pwgen-for-bios, DellBIOSTools, the Rex98
  GUI, and our firmware-faithful implementation on 5 serials × 2 encoders (§13.12).
- The tables and MD5 schedule in the tools are byte-identical to the ones inside
  real Dell firmware modules (§13.12, 90+ modules, 2015–2026) — i.e., the public
  generators match what the machines actually run.

**Reproduction workflow (legitimate, no dump needed):** self-host
`pwgen-for-bios` (or use DellBIOSTools GUI), enter YOUR machine's `<tag>-<suffix>`,
try the generated password(s). For E7A8 two passwords are produced — try both.
For HDD passwords, input is the drive serial + `-D35B`-style suffix.

**Limitations:** suffix era only; some families need the specific keyboard
layout assumption; A95B/595B HDD variants have quirks (see dogbert's code); no
support for anything 8FC8+; community-maintained (no vendor endorsement).

---

## 4. #2 — 8FC8/CF1B generation (2019+): what exists (and what doesn't)

- **craigsblackie/8FC8_Patcher** — https://github.com/craigsblackie/8FC8_Patcher
  (16 ★, Python, 2026-03). Author = MDSec's Craig Blackie. `8FC8_Patcher.py`
  (106 lines, read in full): Intel-sig gate `5AA5F00F03` (first 0x1000), then
  regex `^00FCAA([0-9A-F]{2,4})000000([0-9A-F]{2,})$` → replace with `00FC00`,
  second `^00FDAA…` → `00FD00`, scan window ≤ 0x160000. Puts the BIOS in
  **manufacturing mode**: removes password enforcement, keeps settings, BitLocker
  still boots, Service Tag changeable. **This is the exact code DellBIOSTools'
  "BIOS Unlocker" ships** (identical function names) — the lineage origin.
- **Rexer98/Rex98-Dell-8fc8-Patcher** — https://github.com/Rexer98/Rex98-Dell-8fc8-Patcher
  (20 ★, 2024-12). Original release; binary-only (RAR) — "drag the bin file to
  the exe", "works on all 8FC8 lock".
- **What the patch actually does** (our independent RE, REPORT §13.10): the
  patterns are **enrolled password records in the Dell EC record store** (IFD
  region 8; `00 FC|FD <type> <idx> … AA <payload>`); the 3-byte overwrite zeroes
  the type byte (AA=active → 00=cleared), disabling the record without touching
  the sealed payload. Verified byte-exact on a real locked 3090 dump.
- **Required input:** full SPI dump + external programmer (or flashrom with
  write access). No Service-Tag keygen exists for this generation — verified at
  table level: the 8FC8 output alphabet exists in Dell firmware but in **no**
  public tool (§13.12–13.13).
- **Limitations:** needs hardware access; patches are version-sensitive (issue
  #9 "Intel signature not found" on some dumps); does not reveal the original
  password (disables it); Dell may harden in future firmware.

Adjacent (this repo, clearly labeled as OUR work, not an external find): the live
EC **challenge protocol** keygen `dell_cf1b_probe` (REPORT §13.6) is the only
known non-programmer route for 8FC8/CF1B — no equivalent exists in any public
tool (verified §13.11–13.13).

---

## 5. #3 — Dell-specific firmware-analysis tools (acquisition step)

- **platomav/BIOSUtilities** — https://github.com/platomav/BIOSUtilities
  (1086 ★, Python, pushed 2025-07). `DellPfsExtract.py` parses **all Dell PFS
  revisions** (LZMA/ZLIB/BIOS-Guard-PFAT) from update packages (.exe/.rcv/.cab)
  and emits final firmware components (BIOS, EC, ME). `pip install biosutilities`.
  This is the maintained Dell-specific extractor; used alongside our own
  `collect_from_catalog.py` pipeline (which uses `uefi_firmware`'s PFS parser).
- **LongSoft/PFSExtractor** — https://github.com/LongSoft/PFSExtractor
  (52 ★, C++, archived 2022, 2017 vintage). The original primitive extractor;
  superseded by BIOSUtilities / UEFITool NE.
- **UEFITool / UEFIExtract / UEFIFind** (LongSoft) — the standard GUI/CLI for
  browsing extracted Dell BIOS regions, locating SystemPwSmm/PasswordMgrDxe
  modules, NVRAM stores, etc.
- **uefi_firmware (Python)** — pip-installable PFS/FFS parser used in this repo.

Reproduction (this is exactly our §13.8 pipeline): `DellPfsExtract` (or
uefi_firmware) on a Dell update package → BIOS region → UEFITool/Ghidra to reach
the pw modules; flashrom + CH341A to read a machine's SPI.

---

## 6. #4 — Generic UEFI/SPI toolchain (combine as needed)

- **Ghidra** (+ efiXplorer plugin): what the MDSec/AmberWolf researchers used on
  SystemPwSmm; what we used for the EC/pw-module RE (§12–13). Free.
- **IDA Pro**: commercial alternative.
- **CHIPSEC** (Intel): platform security tests (SMM/DMA/BIOS write protection);
  not password-specific but validates flash-protection posture before/after work.
- **binwalk**: signature scan inside dumps (useful to locate compressed blobs).
- **flashrom**: SPI read/write (external programmer or host LPC).
- **NVRAM parsers**: UEFITool's NVRAM browser + Dell DVAR/record-store scanning
  (dellpwn for DVAR; our `rex98_patcher.py --store` for the EC record store).

---

## 7. #5 — Public security research & CVEs on Dell password implementations

- **CVE-2026-40639 / DSA-2026-197** (see §2) — the definitive published research
  on Dell BIOS password *storage*: reversible XOR in DVAR, key leakage via null
  padding, history-record attacks, salted-hash recommendation. Writeups:
  mdsec.co.uk (2026-07-10), blog.amberwolf.com (2026-07), plus press coverage.
- **The suffix/master-password system itself** (dogbert 2011, hpgl 2007): the
  original public RE establishing that pre-2019 Dell master passwords are a
  deterministic function of Service Tag + family suffix — i.e., "predictable
  derivation" as research finding; now embedded in the tools of §3.
- **Community RE of the 8FC8 generation** (badcaps "Thoughts on RE 8FC8 suffix
  logic", Dec 2024 → Jun 2026): chartables extracted via Ghidra, SystemPwSmm/
  PasswordMgrDxe identified, but "exhausted the static references" with no
  algorithm recovered (§13.11) — matches our finding that the password
  validation is the EC challenge, invisible to BIOS-only static RE.
- Older Dell BIOS *security* CVEs (SMM/Boot Guard/updates, e.g. the DSA-2022-224
  chain) affect the 2.0.7-era 3090 firmware but are not password-recovery paths.

---

## 8. Official / legitimate vendor routes (no RE needed)

- **Dell KB 000131024** "How to clear the BIOS password" — official procedure:
  CMOS/RTC reset where applicable, else **Dell support with proof of ownership**
  (out-of-warranty = paid service).
- **Dell Command | Configure / Dell Command | Monitor (WMI)** — can set/clear
  BIOS passwords *with knowledge of the current password* (legit enterprise
  management); cannot bypass a forgotten one.
- **Dell BIOS Recovery** (Ctrl+Esc / recovery image) — recovers a corrupted BIOS,
  does not clear passwords on modern machines.

---

## 9. Verification runs performed in this survey (real data, this session)

1. **Suffix-vector cross-check:** 8/8 `calculateSuffix` vectors from
   pwgen-for-bios' own spec reproduced with our firmware-derived primitives
   (families 2A7B, 1D3B, 6FF1, 1F66, 1F5A, BF97) — see terminal log; plus the
   full-password vector `7G9C0G2-6FF1 → 35c0b0tVb32Z6ivD`.
2. **E7A8:** byte-identical across pwgen-for-bios / DellBIOSTools / Rex98 GUI /
   our implementation (5 serials × 2 encoders, §13.12).
3. **dellpwn core re-execution:** faithful port of `dvar.rs`' short path + filters
   (committed as `bios-analysis/dvar_scan_port.py`, line-referenced) run over the
   8 full-size real forum dumps in the repo:
   - 6/8 contain a DVAR store (Vostro 3681, OptiPlex 3090 ×4, OptiPlex 7480 AIO).
   - The 8FC8/SIVB-era dumps (3090, Vostro 3681): **zero XOR password records** —
     exactly matching the published not-vulnerable matrix (their passwords live
     in the EC record store / SIVB vault, §13.7/§13.10).
   - The 2018-era 7480 AIO dump: 2 candidate records whose keys look like x86
     code bytes — i.e., the scan's known false-positive surface on code regions;
     the full tool's obfuscation-correction/uncertainty stages (not ported) plus
     operator judgment handle these. Honest result: no confirmed DVAR-XOR
     password in our corpus (it is SIVB/EC-era), and the port reproduces the
     algorithm's mechanics and filter behavior on real flash layouts.

---

## 10. Compatibility matrix

| Dell model / generation | BIOS gen / suffix | Existing tool (repo) | Required input | Verified? | Limitations |
|---|---|---|---|---|---|
| Inspiron/Latitude/Vostro/XPS ~2005–2013 | 595B, D35B, A95B, 2A7B, 1F5A | dogbert/bios-pwgen; bacher09/pwgen-for-bios; DellBIOSTools | Service Tag + suffix | yes (source + vectors + firmware tables) | oldest families use scancode output quirks |
| Latitude/Precision/XPS ~2013–2018 | 1D3B, 1F66, 6FF1, 3A5B | same | Service Tag + suffix | yes (vectors incl. OPENSRC-1D3B) | keyboard-layout assumption |
| Latitude E7xxx / XPS 9560 / Precision 3xxx–7xxx XL / Wyse 5070 (AMI Aptio, DVAR era) | any (password in DVAR) | **dellpwn `scan`** | SPI dump | yes (CVE-2026-40639, published per-model results, our port) | programmer needed; fixed in 2026-06+ BIOS |
| Latitude 7220EX/7214/3190/3310/5420R/5424R/7424R, Precision 3430–7920 XL, OptiPlex 7070 Ultra/XE3, Edge GW (advisory list) | DVAR+XOR (per DSA-2026-197) | dellpwn `scan` | SPI dump | vendor-acknowledged (advisory); update BIOS to fix | — |
| Latitude E7250-style older store | — | dellpwn `clear-password` | SPI dump | per writeup/tool | destructive clear, not recovery |
| OptiPlex 3000 / SIVB platforms | SIVB SHA-256 vault | dellpwn `clear-sivb` | SPI dump | per writeup/tool | reverts to previous (usually blank) password |
| OptiPlex/Latitude/Vostro 2019+ (3070/3080/3090, 5X90, CF1B-suffix) | 8FC8/CF1B EC challenge | craigsblackie/8FC8_Patcher; Rex98 patcher; DellBIOSTools Unlocker; (ours: rex98_patcher.py) | SPI dump + programmer | yes (§13.10 byte-exact on real dump) | disables records, doesn't reveal password; no public keygen exists |
| same, no programmer | 8FC8/CF1B | **this repo** `dell_cf1b_probe` (§13.6) | live machine + candidate passwords | §13 (firmware-derived; unique route) | our work, not an external find |

---

## 11. Ranking justification (per the research order)

1. **dellpwn** — the only *existing* tool that recovers actual passwords from
   dumps of affected authorized machines; current (2026-07), CVE-backed, source-
   verified. Exact Dell-specific solution for the DVAR generation.
2. **pwgen-for-bios / DellBIOSTools / dogbert** — exact Dell-specific solution for
   the suffix generation; four consistent implementations; verified against their
   own test vectors and against real firmware bytes.
3. **8FC8 patchers** — existing Dell-specific *recovery* (record disable) for the
   newest generation; verified against real dumps; requires programmer.
4. **BIOSUtilities / UEFITool / Ghidra / flashrom / CHIPSEC / binwalk** — the
   analysis toolchain to acquire and inspect artifacts for any of the above.
5. **New RE** — only needed for what genuinely has no public solution: computing
   (not disabling) 8FC8/CF1B passwords — the §13 challenge protocol (this repo).

---

## 12. Correlating your artifacts (when you provide model/BIOS/suffix/dump)

- **Lockout screen shows `<TAG>-<SUFFIX>`:** suffix in {595B…E7A8} → §3 tools
  (enter tag+suffix). Suffix 8FC8/CF1B/1B58/9ABE/3FE2 → no generator exists; use
  §4 patcher (dump+programmer) or the §13 probe.
- **You have an SPI dump:** run `dellpwn scan` first. If DVAR era → passwords.
  If SIVB (OptiPlex 3000-class) → `clear-sivb` rollback. If 8FC8-era → 8FC8
  patcher (FC/FD records, §13.10); our `rex98_patcher.py --store` decodes the
  EC record census first.
- **You have a Dell update package (.exe/.rcv/.cab):** BIOSUtilities
  `DellPfsExtract` / our `analyze_dell_bios.py` to extract BIOS+EC and compare
  pw modules against the salt/table DBs (`dell_salts_db.py`, `TABLE_BANK`).
- **Model + BIOS version only:** check DSA-2026-197 list for DVAR exposure;
  else classify by generation via the matrix in §10.

---

## 13. Security / scope notes

All routes above require either information displayed by the machine itself
(suffix) or physical access to flash (programmer/flashrom) on hardware you own or
are explicitly authorized to service. Nothing here touches Dell accounts, private
APIs, or third-party systems. Dell's official recovery channel (proof of
ownership) remains the non-technical route. Fixed BIOS versions (June 2026+) close
CVE-2026-40639 — update after legitimate recovery.
