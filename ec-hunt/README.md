# ec-hunt — the agent fetch tool of the CF1B offline-keygen campaign

**Goal:** make the standalone CF1B keygen ("tag + suffix in → master password
out, no machine") by automatically finding the one artifact class that can
complete it: a **plaintext EC firmware image containing the type-6 GENERATE
engine** ("EC程序" — RT809H direct-EC reads of the EC's internal flash).

**Why hunting is needed:** the transform exists only in Dell's backend and in
EC silicon (per-build AES key fused in the chip). Every public update-package
EC payload is sealed; every repair-forum SPI dump carries only boot+tables
with the app sealed. Proven by exhaustion — CF1B_FINDINGS §11.7/§11.8. The
campaign is therefore a standing watch for *new* material, run automatically.

## The pipeline

```
watchlist.txt + GitHub search + sibling-branch relay output
        │  ec_hunt.py  (runs daily via .github/workflows/hunt-ec-firmware.yml,
        │              and on every push touching ec-hunt/**)
        ▼
  ec_classify.py  ── SEALED ──────────────► logged, ignored
        │  (PHCM magic/entropy/chi²/Cortex-M
        │   vector scorer + GENERATE markers:
        │   family-list u16s, salt 8dfc7b25, SHA-256 K-table, alphabet72)
        ├── PLAINTEXT-OLD-ENGINE ─────────► logged (5X90 class, no GENERATE)
        └── PLAINTEXT + GENERATE ── HIT ─► HIT-ALERT.md + quarantine/
                        │
                        ▼
          ec_generate_emu.py (Cortex-M emulation of the GENERATE handler;
          drives {0x21,0x00,0x03,0x06} + tag + family LSB → 32-byte response;
          resp[0:16] = the master) → cross-validated against live
          dell_cf1b_master readouts (VALIDATION-LOG.md) → KEYGEN COMPLETE
```

## Files

- `ec_hunt.py` — the hunter (GitHub-only mode is sandbox-safe; `--allow-net`
  for the Actions runner / local runs with full egress)
- `ec_classify.py` — the classifier (corpus criteria; knows every dead end)
- `ec_generate_emu.py` — keygen-completion harness for HIT images
- `watchlist.txt` — leads to re-check every run (add new leads here)
- `seen.json` — dedupe state (sha256), so every run only processes NEW files
- `HUNT-REPORT.md` — the log of every run
- `HIT-ALERT.md` — created only when the GENERATE engine is found
- `quarantine/` — candidate files kept for analysis (small ones committed)

## What counts as a HIT

A plaintext Cortex-M EC image whose body contains the GENERATE machinery:
≥3 of the EC-routed families {1B58, 9ABE, 3FE2, CF1B, 8FC8} co-located as
u16 immediates (the handler's family dispatch), with the EC-path salt
`8dfc7b25` and/or the SHA-256 K-table nearby. Confirmation is always by
emulation + match against a physical EC readout before any keygen output is
trusted.

## Legal / scope

Firmware and dumps are collected only from public sources for security
research on hardware the operator owns or is authorized to service. The hunt
never touches gated/paid content — it watches for material that becomes
freely available.
