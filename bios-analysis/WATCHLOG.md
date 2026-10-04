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

## Cycle 7 (2026-10-04) — sandbox reset recovery + solution-kit build
- Sandbox was reset to base fbb7085; recovered via anonymous fetch of
  origin/arena/01a087e2-zte (tip c344c23, 2187 files) + re-applied §11.20.6
  (was unpushed when the token expired). GitHub token still invalid — push
  + relay workflows need user reconnect.
- Task: assemble each part of the solution source and pin per-model support
  to each model's LATEST BIOS version (kit build this cycle).
- solution_kit/ built: 5 models pinned to latest BIOS (3410 1.36.0, 3420
  1.47.0, 3080 2.35.0, 3090 2.30.0, 3090UFF 1.44.0); keygen gained
  --model/--list-models; latest-version engine verification: 3080/3090
  modules byte-identical to 2.27.0 reference; UFF = Gen-B EC-only module.
  Kit validated end-to-end (selftest + census + patcher state + clear-sivb).
  Two Latitude latest cabs queued in relay fetchlist.
- 3410 1.36.0 + 3420 1.44.0 latest packages fetched via relay (dl.dell.com)
  and verified: 3410 vault module md5-identical to reference; 3420 module =
  39424B class with 8FC8 routing + standard alphabets; EC lines unchanged
  (3420) / advanced (3410 v1.12.0 bt=0xa29). ALL 5 kit models now
  held+verified at latest. LVFS cab = browser-only (anti-bot).

## Cycle 8 (2026-10-04) — goal re-anchor: (tag,vault) pair hunt + KDF matrix + EC session map
- User re-anchored the goal: per-model keygen producing master passwords.
  Cycle tested the last untested derivation hypothesis and mapped the EC API.
- Sandbox reset AGAIN (base fbb7085, 2nd time); recovered via anonymous
  git fetch origin arena/01a087e2-zte + reset --hard (tip fb67f30) — recipe
  from §Errors re-confirmed.
- Tag-extraction methodology found: CSME '/<TAG>/<PPID>/' strings + SMBIOS
  templates. 4 (tag, vault) pairs recovered (5410 ×3: 92739D3/1CDGTD3/
  GBL3L63; 5430: 9DWPJR3). §11.20.6 conditional door TESTED + CLOSED:
  vault key NOT tag-derived (60 KDFs × 6 modes × 4 pairs, all noise).
  BPT7YL3 = 3090 tag but that dump has no vault — keep watching for a
  3090 dump with both.
- EC session surface enumerated (7 types, T6=GENERATE, T4=data-class query
  {4D624984…}, status map {0,2,6,9,14} — NO tag-mismatch code → donor-
  machine GENERATE hypothesis now top software door; needs one running
  machine of a build to test).
- New tools: tag_vault_inventory.py, dell_vault_kdf.py, dell_ec_sessions.py.
  Findings §11.22. Kit unchanged (oracle-gated).

## Cycle 9 (2026-10-04) — EC content inventory + §11.16 bundle REFUTED (WiFi)
- User asked what the EC stores. Wrote the ingredient list (§11.23.1):
  GENERATE engine + per-build keys + PHCM unwrap keys + per-machine vault
  DEK; one EC dump per build = pure keygen for that build (3 proofs).
- While verifying: REFUTED §11.16's "second EC firmware bundle" — the
  0x7b59fc bundle AND the 0x82d464 "0x6a60 region" are WiFi-card firmware
  staging (802.11ax + BT-coex strings, WPA2 inv S-box, WiFi-SoC download
  record chain 14x32KB to 0x804xxxxx). "NPCX7 EC" identification
  withdrawn; GEN 1.2/1.3 decode-payload door CLOSED as misidentification.
- Whole-32MB clearance scan: NO EC firmware on the 3090 main SPI (0 vector
  tables, 0 AES/SHA tables, chance-level BL density). 3090 EC = internal-
  flash chip like the 3410's.
- Queued: elvikom IPCML-RN/ZB schematic/boardview (3090 EC part number →
  GEN 2 instructions for the user's own model), badcaps 98981 page4 watch.

## Cycle 10 (2026-10-04) — agent status + venue sweep + seller contact
- User asked where the agents are. Relay ran 3x during the session (elvikom,
  pkbiosfix page, pkbiosfix 22-attachment sweep) — all success; both new
  venues are login/paywalled (files DEAD), thread text mined.
- External confirmation (Hackaday 2022): Dell EC firmware encrypted + keys
  fused in EC — the files are not online ANYWHERE by design; public corpus
  is at parity (273 dumps + all packages).
- SELLER CONTACT found on pkbiosfix: master codes for 8FC8/CF1B/3FE2/9ABE/
  1B58/E7A8 via wa.me/923280493988 — practical unlock door + validation
  triple source. Logged §11.24.3.
