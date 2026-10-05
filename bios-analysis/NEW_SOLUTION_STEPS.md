# NEW-SOLUTION STEPS — EC-era suffix keygen (8FC8 / CF1B / 9ABE / 3FE2 / 1B58)

Directive (2026-10-05): **do not use old-suffix source code** (nothing from
the 595B/D35B/…/E7A8 public keygen lineage). Build a NEW solution for the
NEW suffixes. **Every achieved step is committed here** so it is never redone.

Target: `master(service_tag, suffix)` for the EC-era families, offline.

Verified architecture (CF1B_FINDINGS.md §11.1–§11.7, emulation-validated):

    master = RENDER( EC_GENERATE(tag, family_byte) )
      EC_GENERATE: EC-internal session {cmd 0x21, sub 3, type 6};
                   send tag[7]+family LSB; recv resp32 + status
      RENDER (BIOS fn 0x8E18):
        CF1B/3FE2/1B58/9ABE -> resp32[0:16] verbatim (resp[16:32]=2nd cand)
        8FC8                -> alphabet0[(resp32[i]+resp32[i+16])%72]

The EC_GENERATE transform lives in exactly 3 places: Dell backend, sealed
update payloads (AES key fused in EC), and the EC's INTERNAL flash.
=> The single missing input is an **EC-internal flash dump** ("EC程序",
RT809H direct-EC read) of any 8FC8-family machine (2020-21 gen: OptiPlex
3080/3090/5080/7080, Latitude 3410/5410, Inspiron 5401/5501).

## Achieved steps

### Step 1 — DONE (commit: cycle 14, 2026-10-05): the consumer pipeline
`solution_kit/src/dell_ec_keygen.py` — new-suffix-only tool, no legacy code:
  - RENDER maps for all 5 families + §11.3 emulation-evidence selftest
    (CF1B→"ABCDEFGHIJKLMNOP", 8FC8→"2rk9L1Gq53kZkFx["): ALL PASS
  - --render: map a captured 32-byte response to the master code(s)
  - --triage: classifies ANY artifact — validated on the 4 held classes:
      5X90 EC (plaintext PHCM H=6.84 + alphabet + 81 mailbox refs) /
      fleet pkg EC (sealed H=7.99) / 5410 8MB companion SPI (2 sealed PHCM
      slots @0x1000+0x51000, false-positive-free) / 3090 chipread EC region
      (Cortex-M vector table SP=0x20016F84 entry=0xA12C, boot-block H=6.34)
  - NVRAM record-store walker: in an EC-internal dump, record 0x15 IS the
    machine's enrolled MASTER password (plaintext string) — auto-extracted
  - --locate: mailbox-literal (0x400F0110–0x400F011B) function locator for
    wiring a new plaintext image; --keygen: unicorn driver (--handler) that
    runs the GENERATE handler on a dump and renders the code

### Step 2 — hunt the missing artifact (EC-internal dump) — IN PROGRESS
Sources to sweep: Chinese repair ecosystem ("EC程序", RT809H, EC读出,
NPCE285PA0DX / MEC1515 dumps), bilibili/douyin video descriptions,
pan.baidu shares, fixbase/chinafix/vinafix/elektroda (gated — check for
leak mirrors), Telegram (t.me/biosarchive held), Google Drive links in
repair forums. Any free hit → relay fetch → --triage → pipeline.

### Step 3 — docs wiring (README, findings, watchlog) — pending
