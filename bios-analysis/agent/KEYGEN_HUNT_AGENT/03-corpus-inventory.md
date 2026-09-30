# Held corpus (Zte repo, bios-analysis/)

## OptiPlex 3090 machine dumps (32 MB SPI, four distinct machines)

| Dump | State |
| --- | --- |
| collected/raw/OptiPlex_3090_indiafix/…/optiplex_3090.bin | locked-read class |
| …/IPCML-RN ZB MLK REV A00 READ .Bin | locked-read class |
| …/3090 Bios Password Unlocked.bin | password-UNLOCKED |
| collected/raw/indiafix_3090_212037_wb/…/32MB.BIN (sha256 390c0bef…) | unlocked, OK-tested |

All four share the byte-identical core-only EC region (0x6a60) — extract at
collected/ec_region/3090_2.0.7_MEblob_ecregion_6a60.bin.

## Dell packages

- OptiPlex 3090 BIOS 2.0.7 (stages the EC region) + latest (stages NO EC app)
- Latitude 3410 BIOS 1.6.0 (stages 4 sealed PHCM — extracts in collected/ec_region/)
- Latitude 3420/3520 1.13.3 (no visible EC staging; DUB sections opaque — do not re-parse)

## 3410 companion-chip corpus

- 8 MB chip dump (sha256 1095f3ce…f308ef), 16 MB (86e3d208…42b38)
- mediafire + indiafix-wayback corpus (fully analyzed)

## Tools (bios-analysis/)

- dell_master_keygen.py — legacy keygen (--selftest verified)
- dell_cf1b_master.c / dell_cf1b_probe.c — live EC query (Route A; Linux
  prebuilts in bin/: dell_cf1b_master-linux, dell_cf1b_probe-linux)
- dell_unlock_image.py — SPI patcher (Route B, field-proven on the 3090)
- dell_ec_region.py — EC region extraction/analysis
- extract_pw_modules.py — DellPfs/DUB extraction (find_dub), PHCM regex search
- dell_8fc8_patch.py, dell_8fc8_probe.c, ec_*.py, emu_vault.py — supporting analysis

## New tool

- **MEA++ TnD BIOS** (collected/tools/MEA++_TnD_BIOS.exe, 19,390,976 B,
  sha256 baaccef42cec2cc6d9aeac39fc20c337f64d3752d50d25d3944ff05ae5af24de):
  TechNoDev's CSME 18/19/20/21+ repository analyzer (Windows GUI). Loads an ME
  region or full image → CPU family, CSME generation/version, SKU, platform,
  OEM config, firmware date, repository size, file-system stage. Use it to
  correlate CSME build ↔ EC build when matching packages to target machines.
