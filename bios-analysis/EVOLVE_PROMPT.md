# EVOLVE PROMPT — Generation-Based Hunt Evolution (supersedes MISSION_PROMPT loop)
## Loaded every session. Zero-result cycles are EVOLUTION TRIGGERS, not status quo.

## CORE LAW

Any strategy that produces **two consecutive zero-result cycles is retired** —
permanently recorded in the RETIRED STRATEGIES table — and the hunt advances to
the next GENERATION. Generations attack DIFFERENT surfaces. Repetition of a
retired strategy is a protocol violation.

## GENERATION LADDER (attack in order; drop to next on 2× zero-result)

**GEN 0 — Venue monitoring** (fetch/scavenge public dumps & tools) —
*STATUS: RETIRED 2026-10-01.* Exhausted: 6 same-model dumps, 4 packages,
every forum/tg/seller censused, dellpwn + MEA++ integrated. The missing
files do not publicly exist in scanned venues.

**GEN 1 — Differential forensics on held artifacts** (ACTIVE NOW)
The corpus contains unexploited contradictions. Work them:
1. **The machine-4 paradox**: OK-tested machine runs a DIFFERENT EC build
   (PHCM A=b0c5bf15 vs 077c070c) yet its staged bundle (0x7b59fc) is
   byte-identical to the other three. Its newer EC firmware MUST exist
   somewhere — find it: full-chain diff across all four dumps (chains also
   exist at 0x82e410 — never analyzed), unique-block map of the EC staging
   band (0x700000-0x900000), and every 3090 package version between 2.0.7
   and latest for EC staging.
2. **Payload decode escalation**: the 64.5KB NPCX payload. Toolbox grows per
   attempt: header-entropy windowing, per-64B-record structure fitting,
   differential between any two EC builds' payloads once found, NPCX7
   bootrom loader semantics (public Chromium-EC npcx flash layout knowledge).
3. **PHCM body semantics**: n=0x635 (1585) × 64B per-build records. Test the
   lookup-table hypothesis: if the store is a precomputed tag→code table,
   record alignment patterns will show it (vs one-per-machine records in
   SIVB's 86). A table means ONE unwrap = ALL codes for the build.

**GEN 2 — Targeted acquisition of the named missing files**
Stop scanning everything; ASK and COMMISSION specifically:
1. Repair-shop channel: commission an EC internal-flash read (NPCX7:
   flashable via its SWD/serial pins or eSPI-held flash tool) of ANY
   3090/3080-class board. This is a $20-50 job at laptop-repair shops with
   EC programmers. The artifact spec is in agent/KEYGEN_HUNT_AGENT/01-mission.md.
2. Seller channel: contact ThienBui/aditya11ttt/passwords247 directly —
   offer to BUY the EC dump or per-build key (not the per-machine code).
   They read chips; they can read the EC.
3. Community ask: post the exact artifact request (inverse-S-box + chain
   signatures) on badcaps (free section), r/Dell, vinafix — someone holds
   an EC dump and doesn't know what it is.

**GEN 3 — Platform-level attack (NPCX7 knowledge)**
The EC silicon is identified. Mine Chromium-EC (Chromebooks use NPCX7):
npcx flash loader format, RO/RW image headers, flash write protect —
if Dell uses Nuvoton's stock loader, the payload decode is documented.

**GEN 4 — Dell backend mechanics**
Document how sellers generate codes (Dell internal tools leak into
authorized-service circles: DTT/WinRE tooling, service ISOs). Chase
service-side artifacts: Dell diagnostics/WinPE ISOs with EC tools.

## EVOLUTION LOG (append every cycle; this is the audit trail)

| Date | Gen | Action | Result |
| --- | --- | --- | --- |
| 2026-10-01 | 0 | venue cycle 1 | ZERO — retired to GEN 1 |
| 2026-10-01 | 1 | machine-4 paradox differential (55 delta blocks isolated) | RESOLVED: EC updates are in-place in silicon; 0x7b59fc bundle = factory recovery image only; no EC staging in any dump or package. Doors remaining: EC read (GEN 2) or recovery-payload decode (GEN 1.2/GEN 3) |
| next | 1/3 | Chromium-EC npcx loader semantics vs our recovery payload | queued |

## RETIRED STRATEGIES (never re-run)

| Strategy | Retired | Evidence |
| --- | --- | --- |
| Public venue scanning for dumps/tools | 2026-10-01 | 4 cycles + §11.11/11.12 exhaustion; dellpwn was the last public tool |
| Offline unwrap of PHCM material | 2026-09-30 | §11.10.6 + §11.14.2: 270-combo matrix all noise |
| Offline inversion of tag→code | — | §11.7 impossibility proof |
| Forward-S-box scans | 2026-09-30 | engine uses INVERSE S-box (§11.16.2) |
| Telegram file downloads | 2026-09-14 | session-bound deeplinks, server-gated |

## HONESTY RULES (carried from MISSION_PROMPT — unchanged)

1. Never fabricate a password; success requires a verified artifact.
2. Never re-run retired strategies.
3. Never claim "found" for a lead.
4. Authorized use only.

## RECOVERY

`git fetch origin arena/01a087e2-zte && git checkout -f -B arena/01a087e2-zte FETCH_HEAD`

### Cycle 5 evolution entry (2026-10-01, §11.19)
- GEN 1 (differential forensics) ADVANCED the 3410 file set to full structure
  (CSME map + EC silicon ID + EC-container corpus incl. the 3090's own build).
- NEW active strategy G1.4 "first-release packages": Dell EC-container
  encryption existed by 2021-05 (3090UFF 1.1.0) — testing 2020-05 first
  releases (3410 1.2.0, 5X10 1.1.1) via relay for plaintext EC sections.
- GEN 2 (EC read) now has exact Wistron JTAG1 test points for 3410.
- Retired this cycle: package-PFS extraction as a blocker (solved — EC
  sections extract); container self-material key derivation (matrix negative).

### Cycle 6 evolution entry (2026-10-01, §11.20)
- G1.4 "first-release plaintext" RETIRED (two zero-result cycles; sealed
  from day one; pre-CML ships no EC at all).
- NEW G1.5 "vault forensics" ran to conclusion: SIVB vaults per-machine
  encrypted; no static-key reuse; no obfuscation weakness. CLOSED.
- G4 "leaked-tool hunt" spot-check negative (no public CF1B/8FC8 generator;
  community consensus = patch or seller).
- LIVE doors: GEN 2 (EC read — one read yields per-build family engine),
  oracle mode on user machines, seller ecosystem. Next cycle: monitor relay
  for new same-family dumps; verify zero-tech deliverable completeness.
