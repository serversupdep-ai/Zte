# Donor-board EC dump runbook — the path to a standalone CF1B/8FC8 keygen

Situation: a competitor sells/generates CF1B-era master codes ("secret
achievements" — they hold an EC-internal dump or per-build key and won't
share). This runbook gets the same input without them, then converts it
into a standalone keygen with the toolchain already in this repo.

## Why this works (established facts)

- The EC firmware shipped in the SPI image is **AES-sealed** (cross-machine
  analysis: 4 models, byte-identical sealed body, entropy 8.00) — the
  unsealing key is fused in EC silicon, per build. One build leak = every
  machine of that generation.
- Inside the running EC, the **decrypted GENERATE engine** computes the
  master from (service tag, family byte). Our emulation harness already
  runs this engine class and our wire protocol is byte-validated.
- The paid services' entire moat is **one chip-read**. That's all.

## Shopping list (~$110–190 total)

| item | price | notes |
|---|---|---|
| RT809H programmer | ~$90–140 (AliExpress/eBay) | includes EC-read functions; hklrf.com publishes the supported-EC list |
| Donor board: any Comet-Lake Dell parts board — OptiPlex 3080/3090/5080/7080 (SFF/Tower/Micro) or Precision 3640-class | ~$20–50 | **dead is fine** — no CPU/RAM/disk needed, the EC chip just has to be intact. Same build = same engine. |
| (optional) SOIC/clip adapters for the EC package | ~$10 | depends on package |

## Procedure

1. **Identify the EC chip** on the donor board (largest small QFN/SOIC near
   the LPC/flash area; read the marking). Cross-check the marking against
   the RT809H EC support list (hklrf.com).
2. **Read the EC internal flash/RAM** with the RT809H EC function per its
   procedure for that chip. (In the trade this is the standard "EC readout"
   repair-shop operation — Dell/HP/Lenovo board repair videos show it on
   the RT809H routinely.)
3. **Save the raw dump** (`.bin`) — do NOT let the tool "repair/patch"
   anything; raw read only.
4. Send me the file (any file-sharing link).

If the chip is NOT on the RT809H list, fallbacks in order: (a) desolder the
EC and read it in a suitable programmer/socket; (b) EC vendor debug/UART if
present; (c) **easiest: hand the donor board + $10–20 to any TV/laptop
repair shop that owns an RT809H and advertises EC readout** — "dump the EC,
raw file, nothing else".

## What happens when the dump arrives (this side, ready now)

1. `classify` — sealed vs engine present (chi²/entropy + PHCM checks)
2. `ec_recon` — locate the GENERATE entry (the corpus already maps the
   instruction class)
3. emulation harness run — feed (tag, family) pairs, capture 32-byte
   responses
4. **validation gate** — must reproduce the held real-world pairs:
   - `2C90B83-8FC8 → N9NM9j1qRMeGzyyr` (vinafix/ThienBui, public)
   - CF1B corpus vectors (`H2FS5S3-CF1B → shzNyjGRzRN2LLzL`)
5. If it validates → CF1B/8FC8 added to `dell-keygen/keygen.html` as a
   computed suffix: **standalone keygen, same as the competitor's, free.**

## Alternatives (no hardware)

- Keep the daily automated hunt (ec-hunt workflow, PR #6) — a leaked
  EC-internal dump of this build appearing anywhere public gets flagged
  the same day, and this runbook's steps 1–5 then run on it.
- The live EC readout (Route A, free, 10 min) still answers YOUR machine's
  tag anytime — it is the personal-unlock shortcut, independent of this
  keygen-building path.
