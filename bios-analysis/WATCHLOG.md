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

## Cycle 4 — 2026-10-01 (everywhere-sweep: Dell catalog + siblings)
- Fetched: 3080 1.3.10 exe+rcv, 3090UFF 1.1.0 exe+rcv, Dell EC Programming
  Tool WNXXT (sha256 verified). Repo-root BIOS_IMG.rcv == 2.0.7 payload.
- RESULT: all sibling/variant package ME payloads are ENCRYPTED PFS sections
  (EFI/Tiano fail) — no EC material accessible; control on 2.0.7 confirms
  the packages were never plaintext EC sources. EC tool = 2016 SuperIO era
  (NCT66xx, not NPCX7) — archived, no decode value.
- Surfaces closed: Dell public catalog (EC updater), sibling packages.
  Remaining doors unchanged: EC read (GEN 2) / recovery-payload decode.

## Cycle 5 (2026-10-01, §11.19) — minimal-file-set + package EC sections
- 3410 8MB companion chip fully mapped (CSME image; IVBP=PHCM key store;
  RBEP/PMCP/NFTP code partitions; A/B mirror at +0x40000; no EC firmware).
- MOCKINGBIRD zip = Wistron schematic: 3410 EC = MEC1515H (Cortex-M4),
  3510 EC = NPCE285PA0DX (NPCX7 family), EC JTAG pads mapped, flash-share.
- §11.18 corrected: Dell packages DO ship extractable "Embedded Controller"
  PHCM-container sections. 3090's own EC container (bt=0x635, matching the
  user's machine build) now in hand + corpus across 3080/3090/3090UFF/
  3420/3410/3510 (collected/ec_region/pkg_corpus/).
- Container crypto: direct matrix + version-ladder XOR all negative →
  per-build key is EC-side (boot ROM/loader), not container-derived.
- QUEUED (relay): 3410/3510 1.2.0 (first release, 2020-05) + 5410/5510
  1.1.1 (first release, 2020-05) — historical-plaintext door test.

## Cycle 6 (2026-10-01, §11.20) — SIVB vault + generational sweep
- First-release packages 3410 1.2.0 + 5X10 1.1.1: sealed PHCM from day one;
  3070 1.4.4: no EC section at all. Package-plaintext door CLOSED (all gens).
- SIVB vault discovered as the universal Dell EC password/state store
  (3070/7070/3090/3410/5410/3440/5430/7430); format mapped; per-machine
  encrypted content confirmed (zero shared data blocks across machines).
- 3090 locked-vs-unlocked differential: chain+bundle identical (per-build),
  vault + store instances per-machine. 3410 store materials build-uniform.
- Cross-version ECB collision test: negative (only literal padding).
- Public-tool sweep Oct 2026: still no CF1B/8FC8 keygen anywhere public.
- New corpus leads logged: 3440 QUAKEL14, 5430/7430, 5410 LA-J371P dumps
  (PHCM/SIVB architecture current through Raptor Lake).
- dellpwn_port.py clear-sivb upgraded: wired into main(), default = validated
  5552B rollback, --full = whole 16KB vault partition; extended-clear bug
  (would have crossed into MFS files at +0x4000, magic 8778 55AA) caught and
  fixed pre-release; validated on locked 3090 + 3410 8MB dumps.
- RECOVERY_GUIDE.md: Route-B chip-size corrected (32MB), SIVB notes added
  (16KB partition boundary, --full fallback, 3410 vault on the 8MB chip).
