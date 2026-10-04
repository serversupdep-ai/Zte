# Latitude 3410 / 3510 — solution card (latest BIOS 1.36.0)

**Platform:** Mockingbird-L CML (Compal) · EC = Microchip MEC1515H ·
**Suffix family on this model:** CF1B · Family byte 0x1B
**Latest BIOS:** 1.36.0 (2025-09-16, Dell J37H1 / LVFS) — older 1.x BIOSes
use the identical CF1B engine (verified on the 1.2.0→1.6.0 line).

## What works on this model (in order of ease)

1. **Dell support (zero tools).** Call Dell with proof of ownership; they
   issue a recovery code for your service tag. Type it, then Ctrl+Enter+Enter.
2. **Ask the machine's own EC for the master code** (needs one bootable
   Linux on the machine, no disassembly):
   `sudo python3 dell_master_keygen.py --model latitude-3410 --tag <TAG> --suffix CF1B`
   The tool talks to the EC (ports 0x910/0x911), gets the 32-byte response
   and prints the master password (CF1B = first 16 bytes of the response).
3. **Computer shop: SPI patch.** This model has TWO flash chips:
   - 8 MB companion chip (CSME + PHCM EC store + **SIVB vault**) — this is
     where the password state lives,
   - 16 MB chip — pure BIOS, nothing to patch there.
   The shop reads the **8 MB** chip, then either:
   - `dell_unlock_image.py --patch dump.bin --out unlocked.bin` (clears the
     enrolled-password markers), or
   - `dellpwn_port.py clear-sivb dump.bin unlocked.bin` (rolls the SIVB
     vault back — find the vault by the `SIVB` letters; seen at 0x3c3000
     and 0x103000 depending on ME version; never touch past +0x4000 from
     the vault start — ME files live there).

## Verified facts for this exact model

- PHCM EC stores on the 8 MB chip at 0x1000 / 0x41000 / 0x81000.
- EC build tags: 1.2.0→0x9f4 (EC v1.0.1), 1.4.1→0x9f4 (v1.0.3),
  1.6.0→0x9fc (v1.5.1).
- The EC images are factory-encrypted (PHCM) on every public package —
  no readable engine exists in any shipped firmware (proven 2020→2026).
