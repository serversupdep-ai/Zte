# Unlock kit — Dell Precision 3640 Tower · CVZKKD3-CF1B

Everything in this kit comes from the repo's verified bios-analysis corpus
(48/48 public-vector keygen, executed-firmware proofs, emulation-proven EC
protocol) plus this session's own validation. Machine identified via Dell:
**Precision 3640 Tower**, ESC **28055585559**.

## STEP 1 — try the generated codes first (30 seconds, free)

Computed by `dell_keygen.py` (firmware CF1B path + alternates):

| # | Password | Construction |
|---|---|---|
| 1 | `b1GMyMy52zkqJN3s` | CF1B firmware-path primary (BF97 construction, executed-firmware proven for pre-gate firmware) |
| 2 | `32xa002Jg6xsXbY9` | fnA-2A7B-legacy alternate |
| 3 | `JnGkZZ9ZRIRPBm3[` | E7A8 first candidate |
| 4 | `JxNGZ3yqWP26p9G[` | E7A8 second candidate |

Type each at the BIOS lock screen, then **Ctrl+Enter+Enter**.
These are accepted when the machine's firmware is the older era
(the 3090 equivalent: BIOS ≤ 2.0.7). If all four are rejected, the
firmware is the gated era — go to STEP 2.

## STEP 2 — read the master FROM THE MACHINE'S OWN EC (zero hardware)

If the machine boots to an OS (setup/admin password only, not a system
boot password): boot a Linux live USB on the machine and run:

```
sudo ./dell_cf1b_master-linux -t CVZKKD3 -f CF1B
```

It performs the reversed type-6 GENERATE session with the EC
(mailbox 0x910/0x911): sends your service tag + family byte, and the EC
returns 32 bytes — for CF1B the **first 16 bytes are the master code**,
printed as `MASTER CODE (resp[0..15])`. This is emulation-proven
end-to-end against the real 2.27.0 vault module. No algorithm is computed
offline — your machine's own EC is the oracle.

Alternative if you want the owner-set password instead of the master:
`sudo ./dell_cf1b_probe-linux` reads the SHA-256 challenge R from the
live machine; then `dell_cf1b_grind` (compile with
`gcc -O3 -march=native -pthread`) brute-forces/wordlists the enrolled
password (feasible for ≤7 chars or dictionary passwords).

## STEP 3 — if the machine does not boot: SPI dump + patch (proven)

1. CH341A (3.3 V) + SOIC8/SOIC16 clip → dump the full SPI flash (16/32 MB,
   dual-chip systems: either chip may hold the store — dump both).
2. Patch the enrolled-record markers:
   ```
   python3 dell_unlock_image.py --analyze dump.bin   # layout + records
   python3 dell_unlock_image.py --patch   dump.bin   # -> patched_dump.bin
   ```
   (or the equivalent `tools/dell_fc1b_unlock.py dump.bin`)
   `00 FC AA … → 00 FC 00 …` and `00 FD AA … → 00 FD 00 …`
3. Flash back → machine boots in **Manufacturing Mode** (password gone,
   settings intact) → write service tag CVZKKD3 → run the official BIOS
   update from **F12 while still in Manufacturing Mode** → **Alt+F** to
   exit → clean normal boot. Field-proven on CF1B machines (badcaps:
   OptiPlex 7000, Latitude 5500).

## STEP 4 — official route (always available)

Dell support, ESC 28055585559 + proof of ownership (invoice or ownership
transfer at dell.com/support/ownershiptransfer). Works out of warranty.

## Files in this kit

- `dell_keygen.py` — 48-family keygen incl. CF1B path (`--selftest` passes 48/48)
- `dell_cf1b_master-linux` / `.c` — EC type-6 GENERATE session reader (root, bare metal)
- `dell_cf1b_probe-linux` / `.c` — EC challenge (R) reader for the grind route
- `dell_cf1b_grind.c` — double-SHA256 grinder for the enrolled password
- `dell_cf1b_r.py`, `dell_cf1b_session_emu.py` — session math / emulation
- `dell_unlock_image.py` — analyze/patch/guide for SPI dumps (record-store aware)
- `dell_pwgen.py`, `pw_fw_exec.py` — executed-firmware master generation harness
- `rex98_patcher.py` — Rex98-faithful marker patcher (cross-validated)
- `extract_pw_modules.py`, `extract_ec_payloads.py`, `ec_recon.py`, `ec_fleet_census.py` — firmware extraction/reversal

Only use on hardware you own or are authorized to service.
