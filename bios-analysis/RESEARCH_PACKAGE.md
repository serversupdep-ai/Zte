# RESEARCH PACKAGE — Dell OptiPlex 3090 CF1B master-password keygen
## (deliverables per RESEARCH_PROTOCOL.md §6; updated 2026-10-01, cycle 3)

## 1. Research report (full log: CF1B_FINDINGS.md §1-§11.17)

Problem: BIOS admin password challenge→response for EC-era Dell machines
(suffix CF1B/8FC8/9ABE/3FE2/1B58) computed by an engine inside the Nuvoton
NPCX7 EC. Verified findings, each with reproducible evidence in-repo:
- protocol (ports 0x910/0x911, open 21 00 03 06, cmd 0x17, window 0x10-0x1F)
  — §11, firmware-reversed; tools dell_cf1b_master.c/probe.c (bin/ prebuilts)
- response→code maps (CF1B verbatim; 8FC8 alphabet mod 72) — §11.7, selftest
- sealed store: PHCM containers (3090 subtype 01018403, n=0x635), per-build
  determinism proven on 3090 + 3410 corpora — §11.10-§11.11
- key material is WRAPPED; 270-combination cross-build unwrap matrix = all
  noise — §11.10.6/§11.14.2 (offline unwrap impossible)
- EC = Nuvoton NPCX7 (Cortex-M4); AES INVERSE S-box (decrypt-only engine) in
  the factory recovery bundle @SPI 0x7b59fc — §11.16
- staged 0x6a60 region fully mapped (this cycle): boot/config tables only,
  no code; sole code = 64.5KB encoded payload (decode = NPCX boot ROM /
  Nuvoton secure boot); key data at EC 0x80418020+ never staged — §11.16-11.17
- EC firmware updates IN PLACE in EC silicon (machine-4 differential) — §11.17
- public-tool landscape censused to exhaustion (dellpwn CVE-2026-40639 =
  DVAR-XOR recovery, N/A to 3090/SIVB; DellBIOSTools = legacy math + patcher;
  no public generator exists) — §11.12/§11.15

## 2. Algorithm (current, complete except one input)

tag ──(EC mailbox: 0x910/0x911, open {21 00 03 06}, cmd 0x17)──> response(32B)
response[0:16] ──(verbatim)──────────────────────────────────> CF1B master code
alphabet[(resp[i]+resp[i+16]) mod 72] ────────────────────────> 8FC8 master code
legacy families (E7A8…): serial-scramble + MD5 (dell_master_keygen.py)
MISSING INPUT: the EC's response (or the per-build key to compute it offline)

## 3. Code (all in bios-analysis/, runnable)

- dell_master_keygen.py — keygen + maps (--selftest; --oracle resp:HEX)
- dell_cf1b_master.c / dell_cf1b_probe.c — live EC query (Route A)
- dell_unlock_image.py — SPI patcher (Route B, field-proven)
- dellpwn_port.py — DVAR/SIVB tool (dellpwn port; clear-sivb validated)
- master_hunter.py — artifact scanner (inverse-S-box/PHCM/SIVB/DVAR/NPCX)
- relay/fetch_files.py + fetchlist.txt — acquisition relay
- agent/KEYGEN_HUNT_AGENT/ + Agent-Me twin — knowledge agents

## 4. Tests + actual results (2026-10-01)

- dell_master_keygen.py --selftest: PASS (CF1B/8FC8 maps, E7A8 emulation)
- dellpwn_port clear-sivb on locked 3090 dump: byte-exact (0x891000..0x8925af)
- master_hunter.py scan: EC bundle + full 32MB dump — all signatures fire
- offline unwrap matrix (270 combos): NOISE (negative test — reproducible)
- cross-model PHCM determinism table: reproduced on 4 dumps

## 5. Limitations / unresolved (honest boundary)

- EC-era keygen requires: EC internal-flash read (NPCX7 SWD/EC-flash tool)
  OR decode of the 64.5KB Nuvoton-secure-boot payload OR Dell backend.
  These are external dependencies per protocol §7b — actively worked (GEN 2/3).
- Legacy keygen: verified for E7A8-family only on documented vectors.
- Simulated vs target: all static analysis is on real 3090 artifacts (4
  machines); no live-machine test has run (Route A unvalidated on hardware).

## 6. Attribution

dellpwn (R3n5k1/AmberWolf+MDSec, MIT, CVE-2026-40639); Agent-Me (MIT);
Chromium-EC (BSD) — layout knowledge only; MEA++ TnD (TechNoDev);
corpus: indiafix/badcaps/vinafix/dr-bios public threads.
