# Dell BIOS Master Password Keygen — standalone

**`keygen.html`** — the whole keygen in one file. Open it in any browser
(double-click, works fully offline, no server, no dependencies), type the
service tag, pick the suffix, get the master password candidates.

## What it computes

| Suffixes | Guarantee |
|---|---|
| 595B D35B 2A7B A95B 1D3B 1F5A 1F66 6FF1 BF97 E7A8 | **The unlock code** — legacy constructions, proven by firmware execution, 72/72 public vectors |
| CF1B / FC1B (+ 8FC8 family) | **Firmware-path candidates** — accepted on pre-gate (older) BIOSes; on latest firmware no offline keygen can exist (proven) → use the EC readout (`dell_cf1b_master`), the SPI patch (`dell_unlock_image.py`), or Dell support |

Enter a code at the lock screen → **Ctrl+Enter+Enter**.

## Fidelity

- Faithful JS port of `dell_keygen48.py` (the 48-family corpus keygen; legacy
  lineage: dogbert/bios-pwgen → pwgen-for-bios). All lookup tables are
  auto-extracted from the Python original — zero hand transcription.
- **Validated 72/72 vectors byte-exact** (`node test.js`), including the
  public vectors DELLSUX·1F66 → `qHXaL0ntli6Gu4c0`, H2FS5S3·BF97 →
  `shzNyjGRzRN2LLzL`, 7QJ4H42·E7A8 (both candidates).
- Sync SHA-256 included (E7A8 path) — found and fixed the classic
  rotate-left/rotate-right bug during validation.

## Files

- `keygen.html` — the standalone keygen (this is the deliverable)
- `keygen-core.js` — the same core as a Node module (`require("./keygen-core.js").keygen(tag, sfx)`)
- `test.js` + `vectors.json` — the 72-vector validation against the Python ground truth
- `dell_keygen48.py` — the Python original (CLI: `python3 dell_keygen48.py TAG SUFFIX`)

For hardware you own or are authorized to service.
