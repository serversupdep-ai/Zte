# DELL BIOS MASTER-PASSWORD SOLUTION KIT
_per model, pinned to each model's LATEST BIOS version only (verified 2026-10-04)_

## The models (latest BIOS only)

| model | latest BIOS | where | suffix | package |
|---|---|---|---|---|
| Latitude 3410/3510 | **1.36.0** (2025-09-16) | Dell J37H1 + LVFS | CF1B | fetch queued |
| Latitude 3420/3520 | **1.47.0** TGL (2026-07-21) / 1.37.0 ICL | LVFS | CF1B | fetch queued |
| OptiPlex 3080 | **2.35.0** (2026-07-17) | LVFS | 8FC8 | **held + verified** |
| OptiPlex 3090 | **2.30.0** | LVFS (Dell site: 2.28.0) | CF1B, 8FC8 | **held + verified** |
| OptiPlex 3090 UFF | **1.44.0** | LVFS | 8FC8 | **held + verified** |

Version sources: fwupd.org LVFS is Dell's live channel and runs AHEAD of
Dell's own download pages for the OptiPlex fleet (e.g. Dell site still
lists 3080 "1.3.10"/3090 "2.28.0"). Every "held + verified" row means the
latest package's EC containers and vault module were extracted and the
parts below were run against that exact version.

## The parts (all in `src/`, pure Python, no install needed)

1. **`dell_master_keygen.py`** — the master-password generator.
   - EC families (CF1B, 8FC8, 9ABE, 3FE2, 1B58): asks the machine's own
     embedded controller (ports 0x910/0x911) and applies the
     emulation-verified response→master maps:
     CF1B/3FE2/1B58/9ABE = response[0:16] verbatim; 8FC8 = alphabet map.
     Also accepts a captured response offline: `--oracle resp:HEX`.
   - Legacy families (E7A8 etc.): emulates the machine's own vault module
     (`src/firmware/`) — only relevant for pre-EC-era machines.
   - `--list-models` prints the table above;
     `--model <id>` pins and census-checks a run.
   - `--selftest` validates every map against the emulation vectors.
2. **`dell_unlock_image.py`** — the SPI-dump unlock patcher (Route B).
   Finds and clears the EC's "password enrolled" markers (00FCAA/00FDAA)
   in a chip dump: `--state`, `--analyze`, `--patch`, `--wide`, `--guide`.
3. **`dellpwn_port.py`** — DVAR password recovery (older machines) and the
   SIVB vault rollback: `clear-sivb in.bin out.bin [--full]`
   (default 5552 B validated range; `--full` = the whole 16 KB vault
   partition; NEVER write past vault+0x4000 — ME files live there).
4. **`dell_ec_keygen.py`** — NEW-SUFFIX-ONLY pipeline (EC families
   CF1B/8FC8/9ABE/3FE2/1B58; contains no legacy-suffix code). Four modes:
   - `--triage <any file>` — classifies any EC/SPI artifact (plaintext vs
     sealed PHCM, Cortex-M vector table, markers) and, on an EC-internal
     flash dump, walks the NVRAM record store — record 0x15 IS the
     machine's enrolled master password, printed in plaintext;
   - `--render <resp-hex> --suffix CF1B` — maps a captured 32-byte EC
     GENERATE response to the master code(s) (byte-identical to
     dell_master_keygen's maps — cross-validated);
   - `--locate <dump>` / `--keygen <dump> --tag T --suffix F [--handler
     0xADDR]` — finds the EC mailbox handlers in a plaintext Cortex-M
     image and drives the GENERATE session in emulation (needs `pip
     install unicorn`; every other mode is stdlib-only).
   This is the push-button consumer for the ONE missing offline-keygen
   input: an EC-internal flash dump ("EC程序", RT809H direct-EC read) of
   any 8FC8-family machine — OptiPlex 3080/3090/5080/7080 share one EC
   firmware, so a dump from ANY of them completes the 3090 keygen.


## Per-model instructions
One page per model in `models/<model>/CARD.md` — written for a non-technical
reader, in order of ease: Dell support → EC question → shop SPI patch.

## Honest limits (unchanged, evidence-closed 2026-10)
The EC-side transform (service tag → response) is sealed in EC silicon with
factory keys on every model above — no offline keygen for it can exist from
public material (proven across 2019-2026 packages, §11.19-11.20 of
CF1B_FINDINGS.md). The master code is therefore obtained by (a) asking the
machine's EC (part 1), (b) Dell support, or (c) removing the enrolled
password state (parts 2-3, field-proven).

Machine-readable data: `MODEL_PROFILES.json`.

## Donor-factory keygen (any ONE working machine of a model = that model's keygen)

The EC accepts the service tag as a wire input (GENERATE session) and has no
wrong-tag status (§11.22.3) — so a working machine can mint the master for
ANY tag of the same model + EC build:

    # on ANY bootable machine of the model, from a Linux live USB:
    sudo sh src/dell_donor_factory.sh <model-id> <TARGETTAG> <SUFFIX>
    # e.g.  sudo sh src/dell_donor_factory.sh optiplex-3090 H2FS5S3 CF1B

Fleet SIVB vault locations (16KB partition, clear-sivb is magic-scanning):
3070/7070 @0x3000 · 3090 @0x891000 · 3410 @0x3c3000/0x103000 (8MB chip) ·
5410 @0x893000/0x7cf000 · 3440 @0x33a000 · 5430 @0x22b000 · 5500 @0x45000.

Engine parity at latest BIOS (verified this cycle): the 3420 1.44.0 module
(39424B class) carries all 6 password alphabets byte-identical to the
reference engine — local keygen paths are fleet-uniform; 3410 1.36.0 /
3080 2.35.0 / 3090 2.30.0 modules are byte-identical (md5) to the reference.
