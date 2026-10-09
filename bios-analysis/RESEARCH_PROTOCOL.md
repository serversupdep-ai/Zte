# RESEARCH PROTOCOL — instantiated 2026-10-01
## (Autonomous Technical Research and Algorithm Development Agent, per user template)

**Target model:** Dell OptiPlex 3090 (module 212037-1), Nuvoton NPCX7 EC,
Tiger-L platform, 32MB single SPI (XM25QH256B/MX25L25673G).

**Target functionality:** Algorithm mapping service tag (suffix -CF1B and the
EC-era family 8FC8/9ABE/3FE2/1B58) → BIOS master password, without a live
machine. Response→code maps are DONE; the missing piece is the per-build
AES key / EC engine input (spec: agent/KEYGEN_HUNT_AGENT/01-mission.md).

**Available materials:** this repository's full corpus (6 machine dumps, 5
BIOS packages, EC bundle + regions, PHCM extracts, dellpwn port, tools) +
online sources per §1 of the template.

## Operative rules (from the template, binding)

1. Discover/collect → analyze (verified facts vs hypotheses) → develop →
   test/validate → loop. Research log = CF1B_FINDINGS.md §1-§11.17 +
   WATCHLOG.md + EVOLVE_PROMPT.md evolution log.
2. Never fabricate code/results/claims; every conclusion traceable to
   inspected material or a reproducible test.
3. Stopping conditions: (a) validation passes (keygen reproduces a known
   working code), or (b) a named external dependency/limitation blocks
   verification. Current state = (b) with two named doors (§11.17): EC
   internal-flash read, or recovery-payload decode. Neither is a stop —
   both are active work fronts.
4. Deliverables package (§6 of template) maintained at
   bios-analysis/RESEARCH_PACKAGE.md — updated each cycle.

## Cycle queue (live)

1. Chromium-EC npcx boot-header fit vs the recovery payload (RUNNING)
2. GEN 2 acquisition asks (repair-shop EC read; sellers)
3. GEN 4 Dell backend mechanics documentation
