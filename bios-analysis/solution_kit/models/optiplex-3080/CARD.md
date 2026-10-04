# OptiPlex 3080 — solution card (latest BIOS 2.35.0)

**Platform:** Comet-Lake line (LVFS 2.x BIOS series) ·
**Suffix family on this model:** 8FC8 · Family byte 0xC8
**Latest BIOS:** 2.35.0 (2026-07-17, LVFS). Dell's own site still lists
1.3.10/2.28.1 — LVFS is ahead. **Package held and verified.**

## Key verification on the LATEST version

The 2.35.0 vault module (pw_4) is **byte-identical** to the 2.27.0 engine
this kit emulates — the keygen is valid verbatim on the latest BIOS.
EC build tags: 1.3.10 → 0x5e2/0x5d0/0x61b/0x600; 2.35.0 → 0x60d main /
0x64f backup.

## What works on this model (in order of ease)

1. **Dell support (zero tools)** — recovery code with proof of ownership.
2. **Ask the machine's EC** (bootable Linux, root):
   `sudo python3 dell_master_keygen.py --model optiplex-3080 --tag <TAG> --suffix 8FC8`
   8FC8 master = alphabet map over the 32-byte response (printed for you).
3. **Computer shop: SPI patch** — the classic 8FC8 patcher route:
   `dell_unlock_image.py --patch dump.bin --out unlocked.bin`
   (or `--wide` for the 6-byte variant; `--state` first to check the lock
   state). SIVB rollback via `dellpwn_port.py clear-sivb` is the
   alternative.
