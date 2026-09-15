# Route A validation log — field runs of `dell_cf1b_master`

Registration of pending/completed physical validations of the EC type-6
GENERATE readout (RECOVERY_GUIDE Route A / CF1B_FINDINGS §11.5). Emulation
proof: end-to-end on the OptiPlex 3090 2.27.0 vault module (instruction-
level, response→code map fn 0x8E18 all branches). Physical runs:

## Pending

### V2 — Dell Precision 3640 Tower, CVZKKD3-CF1B (registered 2026-09-14)
- **Generation match:** Comet Lake, same era as the 3090 testbed. Real 3640
  dumps in the corpus (ifix_19 ×2) carry the new-generation 43,008 B CF1B
  module — same construction/salt `8dfc7b25` as the 3090 2.27.0 module;
  EC record store: single enrolled password (FD record, 64 B).
- **Run plan:** Linux live USB, prebuilt static binary (no gcc — avoids the
  tooling failure the 3450 volunteer hit on 2026-09-13 before the #4/#5
  prebuilt instructions). Binary: `cf1b-research/kit/dell_cf1b_master-linux`
  (branch `arena/01a0a05b-zte`), sha256
  `472bf357ff3bbb72a837bd9716063e14902e3ae1da53b50a347a4e15a909f3a5`,
  byte-identical rebuild of `dell_cf1b_master.c` (gcc -O2 -static).
- **Command:** `sudo ./dell_cf1b_master-linux -t CVZKKD3 -f CF1B`
- **Fallback variants if gated:** warm-reset-into-Linux with the challenge
  screen pending (no power-off); `resp[16..31]` second half as alternate;
  `dell_cf1b_probe` diagnostics on failure.
- **Result:** _pending — will record response hex + status byte, or success._

### V1 — Latitude 3450, 9ABE, BIOS 1.22.1 (volunteer @iLLuSiVeAiRFoRCe, issue #3)
- 2026-09-13: gcc/sudo commands failed locally; no code obtained. Prebuilt-
  binary instructions issued in #4/#5. Result still pending.

## Completed

_(none yet — Route A's first physical confirmation is still open)_

## Reporting format

For each run record: model, service tag, suffix family, BIOS version if
known, exact terminal output (response hex, status byte), and the outcome
(unlocked / gated-by-state / mailbox-idle / family-path difference).
