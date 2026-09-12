# RECOVERY GUIDE — OptiPlex 3090, service tag H2FS5S3, suffix CF1B (BIOS 2.27.0)

This is the practical hand-off for the target machine. Everything below is
backed by the analysis in CF1B_FINDINGS.md (§1–§11) and FINAL_REPORT.md; the
offline-keygen question is closed there — no algorithm exists in public
firmware for the EC-era families (proven by exhaustion, §11.7), so recovery
runs through one of the three routes below, best-first.

---

## Route A — ask the machine's own EC for the master code (no disassembly)

**Tool:** `dell_cf1b_master.c` · **Time:** 10 minutes · **Hardware:** none
(besides the machine) · **Risk:** none (read-only session)

The 3090's EC computes the master from (service tag, family byte) on request
— that is literally what the BIOS password screen does internally. The tool
performs the identical exchange from Linux.

1. Boot any Linux live USB (Ubuntu) on the 3090.
2. Terminal — either the C tool:
   ```bash
   sudo apt update && sudo apt install -y gcc
   gcc -O2 -o dell_cf1b_master dell_cf1b_master.c
   sudo ./dell_cf1b_master -t H2FS5S3 -f CF1B
   ```
   or the all-families Python keygen (same session, plus local families):
   ```bash
   sudo python3 dell_master_keygen.py --tag H2FS5S3 --suffix CF1B
   ```
   (`--suffix E7A8` etc. works fully offline via module emulation;
   `--selftest` validates the maps against the emulation vectors.)
3. Read the `MASTER CODE (resp[0..15])` line.
4. Reboot → BIOS password prompt → type the code → **Ctrl+Enter+Enter**.

What the outcomes mean:

| Output | Meaning / next step |
|---|---|
| 16-char code | That is the master. If the prompt rejects it, try the second half (`resp[16..31]`) as well and report both. |
| `status byte: XX (EC error code)` | The EC gated the session by machine state. Re-run with the challenge screen up (reboot to the prompt, then warm-reset into Linux without powering off). |
| `session failed` / short response | The mailbox was idle or the family byte path differs on your EC build. Run the diagnostic: `sudo ./dell_cf1b_probe --family CF1B` and keep both outputs. |

Notes: bare metal as root only (VMs trap port I/O). Nothing is written to
the EC — the tool only sends the tag and receives.

## Route B — SPI dump → patch (field-proven on the 3090 itself)

**Tool:** `dell_unlock_image.py` · **Hardware:** CH341A programmer + SOIC8
clip (or 1.8 V adapter for 1.8 V flash) · **Time:** ~1 hour

The badcaps 3090 thread (2022–2023) proved this exact flow on locked 3090s
(tags 2RCDXM3, 4JD7KN3, 8LHR0N3):

```bash
# 1. Dump the SPI (16 MB) with your programmer; save a pristine copy.
# 2. Analyze + patch a copy:
python3 dell_unlock_image.py --analyze dump.bin
python3 dell_unlock_image.py --patch dump.bin --out unlocked.bin
#    (--wide if the markers aren't found; --wipe-store as last resort)
# 3. Reflash unlocked.bin, then first boot:
#    F12 → Manufacturing Mode path: disable Absolute, write the service
#    tag, save, Alt+F to bypass. In-mode F12 BIOS update to restore a
#    clean image. Full walkthrough: --guide
python3 dell_unlock_image.py --guide
```

Chip: 3090-class boards carry a W25Q256-class 32 MB or 16 MB Winbond SPI
(sibling 7090 micro documented 32 MB WSON8; check yours first).

## Route C — Dell support readout (zero hardware)

Dell issues the recovery key with proof of ownership — confirmed working
out of warranty for 8FC8-era machines (2023–2025 field reports). Entry
convention at the prompt: type the key, then **Ctrl+Enter+Enter**.

---

## Closed ends (do not spend time on these)

- Offline keygen for CF1B/9ABE/3FE2/1B58/8FC8 — impossible from public
  data; the transform is sealed in EC silicon (§11.7: 150+ EC payloads
  censused, 206 BIOS modules table-scanned, zero parameters anywhere).
- CMOS/NVRAM battery pull, PSWD jumper — the 3090 generation has neither
  (§10.5).
- Legacy-suffix keygens (any tool offering BF97/DVAR math for CF1B) —
  field-rejected on this machine and architecturally unreachable.

## Validation in flight

A volunteer with a locked Latitude 3450 (9ABE) is running the Route-A tool
on their machine (issue #3). Their result — success or diagnostic pattern —
will be recorded here when it arrives.
