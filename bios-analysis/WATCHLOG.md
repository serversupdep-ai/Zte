# Hunt watch log (per MISSION_PROMPT.md loop)

## Cycle 1 — 2026-10-01
- FETCH: relay run (t.me/s/biosarchive, vinafix 45618, badcaps 98981, dr-bios 68894)
- SCAN: all pages landed; tgbiosarchive page live (msgs thru 2026-10-01) — NO Dell/
  3090/CF1B posts in current window; vinafix + badcaps returned thin stubs this pass
  (venue flakiness, retry next cycle); dr-bios 403. The t.me "dl" = the known 6,391-B
  session-bound stub (telegram FILE route stays closed).
- TOOL SWEEP (GitHub, early): no new Dell EC/password tools
  (dell-ec-ladder-override already censused; 595B keygen = ancient legacy).
- INFRA: agent twin rebuilt after sandbox reset (knowledge from repo canonical copy,
  8 docs, grounding verified via web UI). master_hunter.py verified on EC bundle +
  full 32MB dump (all signatures fire; DVAR dedupe fixed).
- RESULT: no new artifacts. Next cycle: retry vinafix/badcaps fresh pages, check
  t.me/s/biosarchive weekly, GitHub sweep monthly, issue #5 unchanged.

## Cycle 2 — 2026-10-01 (GEN 1, EVOLVE_PROMPT)
- Machine-4 paradox differential: RESOLVED (see §11.17). EC updates in-place;
  staged bundle = factory recovery image. No EC material in dumps beyond it
  or in any package (inverse-S-box re-scan included).
- Next: Chromium-EC npcx flash/loader semantics vs recovery payload (GEN 3
  overlap); GEN 2 asks (repair-shop EC read commission; sellers).

## Cycle 2b — 2026-10-01 (GEN 3 knowledge intake: Chromium-EC npcx)
- Chromium-EC npcx facts landed: flash images carry a BOOT HEADER
  (CONFIG_BOOTHEADER_SIZE); NPCX boot ROM copies RO/RW images from flash to
  SRAM (download_from_flash ROM API); RO ~flash-0x0.., RW at 0x20000 class
  offsets; RO hardware-write-protected at factory. Nuvoton secure boot
  (KPROM/signature) matches our encoded payload observation.
- Implication for our bundle: components at 0x80402000 (0x5aac) and
  0x8040e000 (0xfb4) = EC-internal-flash images; the 0xfb4 component starts
  non-vector (encoded), the 0x5aac starts with vectors. The 64.5KB payload
  (0x300-0x10330) is unreferenced by the two records — likely a third image
  (RW?) with a boot header we can now recognize.
- NEXT ACTIONS (queue): (1) fetch npcx boot-header struct from
  chromiumos/platform/ec chip/npcx (config_chip.h / booter defs) and match
  against bundle offsets 0x300, 0x10de0, 0x117f0 surroundings;
  (2) re-map bundle under Dell flash layout (RO@0x2000, RW@0xe000);
  (3) GEN 2 asks remain open.

## Cycle 3 — 2026-10-01 (RESEARCH_PROTOCOL cycle 1: NPCX header fit + region re-parse)
- Chromium-EC npcx facts applied; region layout RE-PARSED correctly for the
  first time (previous comp split was wrong):
  * 0x82d44c region = [rec1 {7,0xfbc,0x8040e000,0xfb4}] + compB@+0x10 (0xfb4:
    VECTOR TABLE {SP 0x20016f80, entry 0xa128, SP 0x20016f84, entry 0xa12c} +
    dense config/pinmux tables incl. NPCX MMIO 0xf0xxxxxx values)
    + [rec2 {7,0x5aac,0x80402000,0x5aa4}] @+0xfc4 + compA@+0xfd4 (0x5aa4:
    pure data/config tables — incl. the hot 0x804070cf refs)
  * compB vectors' entry 0xa128 lies INSIDE the encoded payload's EC-flash
    footprint (0x80400300-0x80410330) => the staged 0x6a60 region contains
    NO executable code; the ONLY code = the 64.5KB encoded payload.
  * Bundle payload is NOT the EC flash image verbatim (compA/compB heads
    absent from it); its head region also carries MMIO-init-style data.
- CONCLUSION (verified): EC staged layout fully mapped; decode of the main
  app is performed by the NPCX boot ROM (Nuvoton secure boot, KPROM) —
  matches §11.16.6. Static decode requires either the boot ROM's key
  (silicon) or a same-generation Nuvoton SDK/loader leak (GEN 2/3 queue).
