# FINAL REPORT — Existing, verified solutions for Dell BIOS password recovery
## (Dell laptops/desktops, authorized-hardware analysis)

Scope: Dell-only, existing/verified solutions first, no invented algorithms.
Every claim below is backed either by (a) source-code inspection of the cited
repository, (b) public test vectors reproduced by our tooling, or (c) executed
firmware from official Dell update packages. Companion documents in this repo:
`DELL_TOOLS_SURVEY.md` (tool census), `REPORT.md` (full research log §1–§14),
`FINDINGS_5X90_EC.md` (EC engine reversal), `ec_fleet_census.py`,
`pw_fw_exec.py`.

---

## 1. Best existing Dell tool/repository (ranked per research order)

### #1 Exact Dell-specific existing solution — `pwgen-for-bios` (bacher09)
* **URL:** https://github.com/bacher09/pwgen-for-bios (web UI: bios-pw.org)
* **What it is:** JavaScript master-password generators, Dell families:
  **595B, D35B (HDD), 2A7B, A95B, 1D3B, 6FF1, 1F66, 1F5A, BF97, E7A8**,
  plus Dell Insyde (Latitude 3540, DES-based).
* **Source inspection:** `src/generators/dell/` — `keygenDell()` dispatches
  per suffix to `Tag595B/Tag1D3B/Tag6FF1/Tag1F66/Tag1F5A/TagBF97/TagE7A8Encoder`
  classes (scrambled-table Feistel-style encoders), `calculateSuffix()`
  (0xAA-XOR bit select over reversed tag bytes → table[r % len]), and the
  Latitude 3540 DES-ECB variant with non-standard bit order (do NOT substitute
  a FIPS DES library) and masterKey ASCII `"23AAFFAD"`.
* **Required input:** service tag (7 chars) + on-screen suffix, or HDD serial
  (11 chars) for D35B.
* **Verified:** YES — the full public vector set (21 service-tag + 14 HDD +
  DES vectors) is reproduced bit-exactly by `bios-analysis/dell_keygen.py
  --selftest` (ALL PASS), and encoder classes are byte-identical to
  DellBIOSTools V2.5 on random blocks.
* **Supported generations:** ~2004–2016 Dell consumer/commercial
  (Inspiron/Latitude/Precision/Vostro/OptiPlex/XPS era of the listed
  suffixes).
* **Limitations:** none for its generations; does NOT cover 8FC8/CF1B-era
  (2019+) machines.

### #2 Exact Dell-specific existing solution — `DellBIOSTools` (chromebreakerdev)
* **URL:** https://github.com/chromebreakerdev/DellBIOSTools (V2.5, actively
  maintained through Oct 2025 per Badcaps thread)
* **What it is:** Python; `keygenDell(tag, suffix)` (same public families),
  a BIOS patcher, Asset Tag Manager, portable-exe builder.
* **Verified:** YES — encoders byte-identical to pwgen-for-bios; independently
  produces `keygenDell("H2FS5S3","BF97") == shzNyjGRzRN2LLzL`.
* **Limitations:** same generation ceiling as #1.

### #3 Dell dump-side recovery method — `dellpwn`-style DVAR XOR (CVE-2026-40639 lineage)
* **What:** X-variable obfuscation in Dell record stores is a repeated-key XOR
  (DVAR); recoverable from an authorized SPI dump.
* **Verified:** YES — REAL recovery demonstrated on a corpus Latitude E6520
  dump (cocka/speed10 pattern; history pattern replayed). Cross-machine
  repeats in the corpus are firmware false-positive signatures —
  `dvar_scan_port.py` (SIVB + E7250 ports, self-tested) reproduces the scan.
* **Input:** authorized SPI dump. **Limitations:** pattern-dependent; applies
  to machines whose stores use the XOR'd DVAR encoding.

### #4 Dell firmware-analysis infrastructure (existing, general)
* **BIOSUtilities** (platomav/BIOSUtilities) — Dell PFS/DBR/DCU parsing;
  used by our `extract_pw_modules.py` / `extract_ec_payloads.py`.
* **uefi_firmware (py)** + **UEFITool/UEFIExtract** — capsule/FV/FFS
  extraction (all Dell BIOS update packages).
* **Ghidra / IDA / capstone** — module disassembly (pw modules are x64 PE,
  PDB paths embedded).
* **flashrom / CH341A+asprogrammer** — authorized SPI dump read/write.
* **binwalk, CHIPSEC** — generic; CHIPSEC for UEFI-variable/NVRAM inspection.

### #5 New reverse-engineering contributed in THIS repo (was necessary)
For the 2019+ generations no public tool exists (verified: public tools
contain zero 8FC8/CF1B knowledge — see REPORT.md §10/§12). Our additions:
* `dell_keygen.py` — 48/48 keygen families, public-vector selftest, plus the
  CF1B path (`keygen_cf1b`) and challenge-hash tooling.
* `pw_fw_exec.py` — **executes the actual Dell pw-module PE firmware**
  (OptiPlex 3090 2.0.7 + 2.27.0) under unicorn x86-64 to generate/verify
  master passwords; proved the era gate is a single lookup-sentinel constant
  (0xFF → 0xFFFF) and that the BF97 fallback ships unchanged in 2.27.0.
* `ec_recon.py` / `ec_emulate.py` / `ec_pw_driver.py` — EC firmware reversal
  harness (Thumb-2); full-session emulation of the EC password engine.
* `ec_fleet_census.py` — 122 EC payloads census (only 5X90 plaintext; the
  rest AES-sealed).
* `dell_cf1b_probe.c`, `rex98_patcher.py`, `analyze_forum_dumps.py`,
  `dvar_scan_port.py`, `build_salts_db.py`.

---

## 2. Compatibility matrix

| Dell model / generation | BIOS generation (suffix) | Existing tool/repo | Required input | Verified? | Limitations |
|---|---|---|---|---|---|
| Inspiron/Latitude/Precision ~2004-2011 | 595B, 2A7B, A95B, 1D3B, 6FF1, 1F66, 1F5A | pwgen-for-bios; DellBIOSTools | tag + suffix | YES (public vectors, 48/48) | era only |
| HDD password (ATA) | D35B | pwgen-for-bios | 11-char drive serial | YES (14 vectors) | era only |
| Inspiron/Latitude 2014-2016 | E7A8 (+second) | pwgen-for-bios; DellBIOSTools | tag + suffix | YES | era only |
| Latitude 3540 (Insyde) | 16-hex + tag | pwgen-for-bios | hash16 + tag | YES (DES vectors) | valid iff output all-hex |
| Latitude E6520-era w/ SPI dump | DVAR-XOR stores | dellpwn method / `dvar_scan_port.py` | authorized SPI dump | YES (real corpus recovery) | pattern-dependent |
| OptiPlex 3090 ≤2.0.7 | CF1B (per-machine cfg) | **this repo**: `dell_keygen.py H2FS5S3 CF1B`; firmware proof `pw_fw_exec.py` | tag + suffix | YES — generated by executing the actual 2.0.7 module | — |
| OptiPlex 3090 2.27.0+ | CF1B | same password; `dell_cf1b_probe.c` oracle / `rex98_patcher.py` | tag; live machine for probe | YES (fallback proven identical; EC store-and-compare) | owner-set pw stays EC-sealed |
| 2019+ Latitude/OptiPlex 8FC8 | 8FC8 | **no public offline keygen exists** (descriptor=NULL stub; algorithm lives EC-side) | EC dump (sealed) or live probe | design documented | EC firmware AES-sealed in 118/122 corpus payloads |
| Recent XPS/Inspiron (EC-sealed) | various | none public | — | — | sealed EC; out of scope offline |

---

## 3. Reproduction workflows

### pwgen-for-bios (existing, for its generations)
```
git clone https://github.com/bacher09/pwgen-for-bios
# open index.html (or the released web build); enter tag + suffix, e.g.
#   1234567-2A7B  →  master password
```
Cross-check offline with our vector-complete port:
```
cd bios-analysis && python3 dell_keygen.py 1234567 2A7B
python3 -c "import dell_keygen as dk; dk.selftest()"   # public vectors, ALL PASS
```

### DellBIOSTools (existing)
```
git clone https://github.com/chromebreakerdev/DellBIOSTools
python DellBIOSTools.py   # 'Password Generator' → tag + suffix family
```

### Firmware-derived CF1B master (this repo — executed Dell firmware, not a reimplementation)
```
cd bios-analysis
python3 dell_keygen.py H2FS5S3 CF1B     # → shzNyjGRzRN2LLzL (+alternates)
python3 pw_fw_exec.py                   # executes the REAL 2.0.7 + 2.27.0
                                        # pw_4 modules; both produce
                                        # shzNyjGRzRN2LLzL (ALL PASS)
```
On-machine validation (2.27.0+): `dell_cf1b_probe.c` (EC challenge oracle,
sub=1/type=3/family=0xCF1B) or `rex98_patcher.py --patch`.

### Authorized SPI-dump analysis (DVAR/XOR era)
```
cd bios-analysis && python3 analyze_forum_dumps.py <dump.bin>
python3 dvar_scan_port.py <dump.bin>    # DVAR/SIVB/E7250 ports, self-tested
```

### Dell package unpack pipeline (existing tools combined)
```
python3 extract_pw_modules.py OptiPlex_3090_2.0.7.exe <outdir>   # pw modules
python3 extract_ec_payloads.py OptiPlex_3090_2.0.7.exe <outdir>  # PHCM EC bins
# UEFITool/UEFIExtract GUI equivalents for manual exploration; Ghidra for
# the extracted x64 PE pw modules (PDB path embedded in .data).
```

---

## 4. Evidence the methods work

1. **Public-vector reproduction (existing tools):** dell_keygen selftest
   reproduces the complete pwgen-for-bios vector set (21 tag, 14 HDD, DES
   vectors, hddOld, Latitude 3540) — ALL PASS.
2. **Byte-identical encoders:** our encoder classes == DellBIOSTools V2.5 on
   random blocks (BF97, E7A8, E7A8-Second).
3. **Executed firmware (new, strongest):** the actual OptiPlex 3090 2.0.7
   pw_4 module, run under unicorn, outputs `shzNyjGRzRN2LLzL` for
   H2FS5S3+CF1B (status 0); 3/3 extra tags match `keygen_cf1b`; 8FC8 stub
   correctly returns EFI_INVALID_PARAMETER; 2.27.0's intact fallback produces
   the identical password when reached (REPORT.md §9.6).
4. **EC engine reversal (execution-validated, 20/20 checks):** the EC
   stores/compares passwords (records 4=admin, 5=system, 0x15=master as
   plaintext strings) and never derives them — so no alternate EC-side
   construction exists to miss (FINDINGS_5X90_EC.md).
5. **Real corpus recovery:** DVAR-XOR recovery on a corpus Latitude E6520
   dump (dellpwn lineage), with FP signatures characterized.

## 5. Known limitations

* **Generation ceiling:** pwgen-for-bios/DellBIOSTools cover suffix families
  through E7A8 (~2016). 8FC8-generation machines cannot be keygen'd offline —
  the algorithm is EC-side and the EC firmware is AES-sealed (118/122 corpus
  payloads; chi-square uniform, no compression).
* **CF1B:** master = BF97 construction (firmware-proven, all eras). But an
  *owner-set* admin/system password's sealed value (EC record 3 / X_enrolled)
  is not recoverable from the host SPI image — recovery requires the master
  or a live verify session.
* **Era gates:** Dell ships single-constant gates (lookup sentinel 0xFF→
  0xFFFF at 2.0.7→2.27.0); tools must be era-aware.
* **Legal/safety:** all of the above only for hardware you own or are
  authorized to test; Dell support (transfer-of-ownership + service tag) is
  the sanctioned channel for locked machines.

## 6. Alternative tools (not ranked #1 and why)

* `biosbypass/Password-generator` — subset of pwgen-for-bios families; use
  pwgen-for-bios instead.
* MicBrain/Master-Password-Recovery-Tool (2012, Dogbert lineage) — obsolete.
* Dogbert's blog keygens — historical source of the public algorithms;
  superseded by pwgen-for-bios.
* `mikrovr/DELL-BIOS-PASSWORD-REMOVAL` — paid/donation service, not open
  source; excluded.
* Dell official DSA advisories (CVE-2025-36579 weak password recovery
  mechanism, CVE-2025-36600, CVE-2023-32453) — no public exploit details;
  relevant as context for why master-recovery flows exist.

## 7. Most promising research path (if no verified solution fits)

For a machine outside every published family (e.g. 8FC8-generation with no
live access): (1) obtain the official BIOS package → `extract_pw_modules.py`
+ `extract_ec_payloads.py`; (2) if the EC payload is plaintext (rare — see
`ec_fleet_census.py` signature), reverse with `ec_recon.py`/`ec_emulate.py`
as done for the 5X90; (3) if sealed, the only remaining routes are the live
EC session oracle (`dell_cf1b_probe.c` pattern) or an authorized external EC
flash read (hardware step, out of scope for dump-only work).
