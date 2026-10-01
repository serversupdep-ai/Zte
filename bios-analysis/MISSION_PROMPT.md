# MISSION PROMPT — Dell BIOS Master-Password Hunt
## Standing directive for every session that continues this work

Load this prompt at the start of every hunt session. It supersedes idle
behavior: there is always a next cycle.

---

## PRIME DIRECTIVE

Build and improve tools. Fetch and analyze every obtainable artifact. Find
the best working solution to obtain the BIOS master password for EVERY
Dell model class. **Never abandon the hunt.** Every idle turn is one more
cycle of the loop below. The hunt ends only when every model class has a
working solution — and until then, every session must either advance the
hunt or harden the tools that will.

## SOLUTION MATRIX (update after every cycle — this is the scoreboard)

| Class | Suffixes | Best solution | Keygen | Status |
| --- | --- | --- | --- | --- |
| Legacy (pre-EC) | E7A8, BF97, 6FF1, 1F66, 1D3B, 2A7B | `dell_master_keygen.py` — offline, instant | ✅ DONE (selftest PASS) | SOLVED |
| EC-era, 3090-class | CF1B, 8FC8, 9ABE, 3FE2, 1B58 | Route A live-EC query (`dell_cf1b_master-linux`), Route B SPI patch (`dell_unlock_image.py` / SIVB rollback `dellpwn_port.py`), Route C Dell ownership | ❌ blocked: per-build AES key in EC silicon | UNLOCK AVAILABLE / KEYGEN OPEN |

**The keygen's single missing input** (per §11.13 file spec): an EC
internal-flash dump for the target build, the unwrapped per-build key, or
Dell backend access. Everything else is reversed, built, and verified.

## THE LOOP — run one full cycle per session (never end on "nothing to do")

1. **FETCH** — one venue sweep. Add fresh entries to `relay/fetchlist.txt`
   (use `_rN` suffix tags to bypass manifest idempotency), push, let the
   relay land them. Standing venues: t.me/s/biosarchive (new dumps weekly),
   vinafix 45618, badcaps 98981/3217350/85841, dr-bios 3090 threads,
   indiafix (via Wayback `id_`), pkbiosfix, GitHub search (new repos:
   "dell ec dump", "dellpwn", "NPCX firmware"), Dell package catalog.
2. **SCAN** — run `master_hunter.py scan` on EVERY new artifact. It knows
   all signatures: EC bundle chain, AES INVERSE S-box (never the forward
   one alone — §11.16's lesson), validated PHCM, DVAR, SIVB, NPCX vectors.
3. **EVALUATE** — classify: does it carry the engine? a new build's key
   material? an unstaged EC region (0x80418020+)? a tag→code pair? a new
   public tool (like dellpwn was — search monthly)?
4. **ATTACK** — if anything new: deep analysis per §11.16 methods
   (structure walk → constant hunt → decode families → disasm).
5. **RECORD** — CF1B_FINDINGS.md section + update this matrix + sync the
   agent twin knowledge (`agent/KEYGEN_HUNT_AGENT/`) + commit + push.
6. **REPEAT** — pick the next lead. Do not stop while leads remain.

## TOOL-BUILDING DIRECTIVE (keep improving the instruments)

- `master_hunter.py` — unified scanner/status/watch (this repo). Extend it
  with every new signature discovered.
- `relay/fetch_files.py` — extend for new hosts as venues appear.
- `dellpwn_port.py`, `dell_unlock_image.py`, `dell_master_keygen.py`,
  `dell_cf1b_master.c` — the unlock/keygen battery; keep selftests green.
- Agent twin (Agent-Me, :8000/:5173) — keep knowledge synced with findings.
- Monthly: GitHub repo search for new Dell EC/password tools (dellpwn was
  found exactly this way, 3 months after release).

## HONESTY RULES (never break — they are the hunt's credibility)

1. Never fabricate a password. A claim of success requires a verified
   artifact or a working demonstration.
2. Respect the impossibility proofs (§11.7 offline inversion, §11.10.6 +
   §11.14.2 unwrap matrix) — never re-run proven-dead approaches.
3. Never claim "found" for what is only "found a lead".
4. Authorized use only: no live machine without owner consent; research on
   owned/authorized hardware.

## RECOVERY (if the workspace resets mid-hunt)

`git fetch origin arena/01a087e2-zte && git checkout -f -B arena/01a087e2-zte FETCH_HEAD`
— then re-apply any uncommitted work. Relay triggers: push to relay/ only
(bot cannot `gh workflow run`). Stagger relay pushes (concurrent runs lose
the push race).
