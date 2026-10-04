# Latitude 3420 / 3520 — solution card (latest BIOS 1.47.0 TGL / 1.37.0 ICL)

**Platform:** CyborgL (TGL; ICL variant exists) ·
**Suffix family on this model:** CF1B · Family byte 0x1B
**Latest BIOS:** 1.47.0 (2026-07-21, LVFS "CyborgLTgl_TI_G") for TGL
models; 1.37.0 for the ICL variant. Dell's own site lists 1.44.0 — LVFS is
ahead.

## What works on this model (in order of ease)

1. **Dell support (zero tools)** — recovery code with proof of ownership.
   Type it, then Ctrl+Enter+Enter.
2. **Ask the machine's EC for the master code** (bootable Linux, no
   disassembly):
   `sudo python3 dell_master_keygen.py --model latitude-3420 --tag <TAG> --suffix CF1B`
   CF1B master = first 16 bytes of the EC response, printed for you.
3. **Computer shop: SPI patch.** Single SPI chip (32 MB class). The shop
   reads the chip, then:
   - `dell_unlock_image.py --patch dump.bin --out unlocked.bin`, or
   - `dellpwn_port.py clear-sivb dump.bin unlocked.bin` (find the `SIVB`
     magic — sibling 3440 RPL has it at 0x33a004; the tool auto-locates).

## Verified facts for this model family

- PHCM EC stores at 0x1000 / 0x51000 / 0xa1000 (sibling dumps).
- EC build tag 0xc82 constant across the whole v1.1.0→v1.4.1 ladder
  (held 1.13.3 package); containers factory-sealed.
- Same CF1B engine generation as the 3410 (Latitude CML/TGL line).
