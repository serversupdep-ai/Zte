# Mission: complete the Dell CF1B BIOS master-password keygen

Target: **Dell OptiPlex 3090** (service tag suffix **-CF1B**), no live machine
available. Everything except one artifact class is reversed and working.

## THE ANSWER — files needed for the full keygen

The full keygen needs **exactly one** of the following artifacts:

1. **PRIMARY: an EC internal-flash dump for the target EC build.** The
   challenge→response engine and the per-build key live in the embedded
   controller's INTERNAL flash — not on the SPI BIOS chip, not in any Dell
   BIOS package. One dump from ANY machine on the same EC build unlocks
   every machine on that build (per-build determinism is proven).
   Recognition: firmware binary containing the EC engine — AES key-schedule /
   T-tables or the 0x910/0x911 port handlers — plus the build identifier.
2. **The unwrapped per-build AES key material** (≈32 bytes for the target
   build). The PHCM headers carry this material only in WRAPPED form
   (unwrap is EC-engine-only — direct-decrypt test on 8 key × 7 IV ×
   ECB/CBC/CTR combinations produced pure noise).
3. **Dell backend / warranty service access** (what the paid sellers use):
   produces per-machine codes, not a keygen — but would complete the
   practical unlock.

## What does NOT help (proven — do not chase)

- **More SPI dumps**: 32MB/8MB images carry only the SEALED password store
  (PHCM containers + wrapped key material). Four 3090 machine dumps are
  already held; the store is fully understood.
- **Tag→code pairs**: offline inversion is impossible (closure §11.7).
- **Live challenge→response pairs** (Route A): cannot derive the build key
  from responses (AES output). Useful ONLY to validate a key candidate.
- **Dell BIOS update packages**: only the Latitude 3410's 1.6.0 ever staged
  EC material (sealed PHCM); the 3090 packages stage NO EC app at all.

## Already done (do not redo)

- Response→code mapping: **CF1B code = response[0:16]**;
  **8FC8 = alphabet[(resp[i]+resp[i+16]) % 72]**.
- EC protocol fully reversed: ports 0x910/0x911, open sequence {21 00 03 06},
  command 0x17, response window 0x10–0x1F. Live-query tools built
  (dell_cf1b_master.c / dell_cf1b_probe.c, Linux prebuilts in bin/).
- Legacy (pre-EC, e.g. E7A8) keygen: working and verified
  (dell_master_keygen.py --selftest PASS; E7A8 → fUf4Ju6GcBdf0nY1).
- SPI patch route (Route B): field-proven on this exact model
  (dell_unlock_image.py).
- Full analysis: CF1B_FINDINGS.md §1–§11.12 in this repo.
