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

### Step 2 — DONE (hunt round 1, 2026-10-05): artifact acquisition map
Swept: dr-bios fleet threads (SPI dumps only), badcaps 7080 thread
(premium-gated SPI), vinafix (paid), chinafix/迅维 (gated downloads, no
fleet EC程序 threads surfaced), Reddit 3410 guide (the "EC" 8 MB file =
companion SPI chip, already held), GitHub (SHP_MEC1515 = unrelated
industrial project; dellpwn repo = DVAR tooling, no EC dumps; prebuilt
mirror = binaries only). KEY FACTS gained:
  - RT809H changelog (kancloud): MEC16xx ECs readable online (flying
    leads), read range = first 192 KB CODE REGION (plaintext); the last
    64 KB parameter area (serial + password) is stored ENCRYPTED but is
    REWRITABLE by the programmer. The GENERATE engine + per-build keys
    live in the code region → an MEC16xx EC read still yields the keygen
    (3410 target: MEC1515H). NPCE288/388 readable via adapter board.
  - Widened target set: OptiPlex 5080/7080 EC bodies are byte-identical
    to the 3090's (§11.7) → an EC-internal dump from ANY of the three
    completes the 3090/CF1B keygen.
  - Confirmed: repair-world "EC dumps" for the 3410/5410 being shared
    freely are the companion SPI (held); true EC-internal reads stay
    trade-gated (vinafix $20 patch sellers, fixbase premium).
  - dellpwn (R3n5k1 repo) = DVAR XOR recovery, CVE-2026-40639 /
    DSA-2026-197, found by AmberWolf + MDSec — owner-set passwords only,
    not the EC master transform. No EC-era engine artifacts in the repo.
Acquisition routes (ranked): (1) seller purchase $10-30 (wa.me/923280493988
— ask for an EC-internal/RT809H dump of any 3080/3090/5080/7080/3410/5410
instead of a code: ONE dump = the whole model's offline keygen);
(2) any repair shop with an RT809H + EC/LPC adapter (minutes per board,
ask for the first 192 KB); (3) standing watch (see WATCHLOG).

### Step 3 — DONE (2026-10-05): docs + cross-validation
- README part 4 = dell_ec_keygen.py wiring (modes + the missing-input
  statement).
- Cross-validated the new tool's render against dell_master_keygen's
  response_to_master/response_to_code2 on all 5 families: byte-identical
  (kit convention: family = 16-bit suffix word 0x8FC8, not the 1-byte
  LSB 0xC8 — noted to avoid future misuse).
- CF1B_FINDINGS cycle-14 entry + WATCHLOG EC-dump watch item.

## Next steps (open)
- Step 4 — DONE (2026-10-05): EC_READ_COOKBOOK.md — the acquisition
  procedure itself (4 routes: SWD for the MEC15xx OptiPlex fleet /
  piernov JTAG recipe for MEC16xx-50xx / RT809H shops / seller purchase),
  with vendor-documented facts: MEC152x = Cortex-M4 + SWD + AES-256/ECDSA
  secure boot w/ OTP keys (the sealing explained); dossalab flash tool
  cloned in-repo; Glasgow applet + SVOD MEC5075 paper + MEC1618/MEC152x
  datasheets fetched via relay.
- Step 5 (OPEN): acquire the actual EC-internal dump (cookbook routes) →
  --triage → --locate → --keygen per build; validate against
  donor-GENERATE output or a seller-provided code on one tag per build.
- Step 6: once per-build keygens validate, fold the build keys into
  dell_ec_keygen.py as a pure-offline table (tag → master, no dump
  needed at run time).
- Step 7 — DONE (2026-10-05, cycle 15): SMI UNLOCK SURFACE from
  never-used sources (libsmbios smi_password.c + kernel dcdbas/wmi
  drivers): dell_smi_unlock.py = live-USB verify+clear of the admin
  password at SMI level (no BIOS screen). Combined with the EC GENERATE
  probe this is a complete self-unlock chain for boot-unblocked machines
  (findings §15.4). Plus ec_artifact_hunter.py agent (81-target venue
  sweep, new telegram channels). Sources archived in-repo for provenance.
- Step 8 (OPEN): field-validate dell_smi_unlock on one fleet machine
  (any locked-but-bootable unit); validate dcdbas vs WMI paths; record
  which selectors the fleet BIOSes accept.
- Step 9 (OPEN, zero-tech user action): download the FREE telegram file
  t.me/biosarchive/24189 (EDW40 LA-H451P 2019 Dell MEC1515-NB board
  archive, .rar) with the Telegram app and hand it to the pipeline
  (dell_ec_keygen --triage). Telegram files need an app account (free)
  — no payment wall. If it holds an EC read → Step 5 completes for the
  MEC1515 build.
- Step 10 — DONE (2026-10-05, cycle 16): EC-FIRMWARE RE WORKBENCH from
  never-used sources (user-directed morluto/REA for PE/artifact lanes +
  capstone/unicorn toolchain): ec_re/dell_ec_engine_re.py. Decoded the
  PHCM container (seal flag, bt, code/data segment map), the full EC
  host-window protocol (0x400F0110-0x400F0114, 0x17 xfer, XOR-0x85
  response channel), the password-session command table, buffers,
  record-store ops and the 16-char table72 verifier — and PROVED the
  stack by emulating the 5X90 response emitter under unicorn
  (bit-exact, EC_RE_FINDINGS.md §3). Negative result that redirects the
  hunt: the 2018 plaintext EC has verify/enroll but NO tag→response
  GENERATE (no C065AEAB GUID, no new family table); ALL 2019+ EC update
  payloads are AES-sealed (45 candidates scanned). Also: the §11.22.3
  "T6 marker" is the full Dell-internal GUID
  C065AEAB-1CDD-494D-BD33-4578E106C700 (zero public hits). Consequence:
  when ANY new-era EC dump lands (Step 5 doors), the pipeline to the
  offline keygen (Step 6) is now mechanical: --scan-plaintext → --xref
  → --dispatch → --emul the GENERATE handler → verified RENDER.
