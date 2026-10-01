# Toolkit

## Analysis (Zte repo, bios-analysis/)
- `dell_master_keygen.py` — legacy keygen + CF1B/8FC8 response→code maps
  (`--selftest` verified)
- `dell_cf1b_master.c` / `dell_cf1b_probe.c` — live EC query over ports
  0x910/0x911 (Route A; needs root on the target machine; Linux prebuilts in
  `bin/`)
- `dell_unlock_image.py` — SPI image patcher (Route B, field-proven on the
  OptiPlex 3090)
- `dell_ec_region.py` — EC region extraction/analysis
- `extract_pw_modules.py` — DellPfs/DUB extraction (`find_dub`) + PHCM search
- `dell_8fc8_patch.py`, `ec_fleet_census.py`, `emu_vault.py`, … — supporting

## Fetch relay
- `relay/fetch_files.py` + `relay/fetchlist.txt` — commit & push to trigger
  the GitHub Actions fetcher (bot-wall guarded; mediafire/gdown/telegram/
  dl.dell.com support)
- syntax: `FILE|<url>|<tag>` and `PAGE|<url>|<tag>` lines
- manifests prevent refetch — `git rm -r` the target dir to force a retry
- runs take ~1.5–9 min; stagger triggers (concurrent runs lose the push race)

## MEA++ TnD BIOS (collected/tools/MEA++_TnD_BIOS.exe)
Windows GUI CSME 18/19/20/21+ analyzer: load a full image or ME region →
CPU family, CSME generation/version, SKU, chipset, OEM config, firmware
date, repository size, file-system stage, FITC version. Used to correlate
CSME builds with EC builds when hunting package-side EC staging.

## Reference documents
- `bios-analysis/CF1B_FINDINGS.md` — the complete analysis (§1–§11.12)
- `bios-analysis/RECOVERY_GUIDE.md` — operator routes A/B/C
- GitHub: issues #3/#4/#5 (issue #5 = Route-A volunteer validation),
  PR #2 (deliverables)
