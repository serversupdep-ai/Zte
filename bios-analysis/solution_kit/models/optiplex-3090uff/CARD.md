# OptiPlex 3090 UFF (Micro) — solution card (latest BIOS 1.44.0)

**Platform:** Meerkat3Tgl (TGL micro) ·
**Suffix family on this model:** 8FC8 · Family byte 0xC8
**Latest BIOS:** 1.44.0 (LVFS). **Package held and verified.**

## Key verification on the LATEST version

This model ships the **new-generation EC-only vault module** (pw_3): the
five EC families (1B58/9ABE/3FE2/CF1B/8FC8) are present with their
alphabets, and the legacy local families are gone. The EC-oracle keygen
path is unaffected — it works on every module generation.
EC build tag 0xc82 has been **unchanged since BIOS 1.1.0 (2021)** — the
2021-vintage EC containers still match the 1.44.0 package.

## What works on this model (in order of ease)

1. **Dell support (zero tools)** — recovery code with proof of ownership.
2. **Ask the machine's EC** (bootable Linux, root):
   `sudo python3 dell_master_keygen.py --model optiplex-3090uff --tag <TAG> --suffix 8FC8`
   8FC8 master = alphabet map over the 32-byte response.
3. **Computer shop: SPI patch** — same 8FC8 patcher route:
   `dell_unlock_image.py --patch dump.bin --out unlocked.bin`
   (+ `--state` pre-check; `dellpwn_port.py clear-sivb` alternative).
