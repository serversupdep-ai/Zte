# Attribution, licensing and safety

## Original work here

`latest_suffix.py`, `vault_inspect.py`, `test_latest_suffix.py`, the reports and
the JSON evidence files in this directory are original work created for this
repository. They are a clean-room re-expression of an algorithm's *arithmetic
specification*; no upstream source file is copied, bundled or translated
line-for-line. The numeric tables (MD5 K-table variant, loop/encode parameters,
72-character alphabets) are factual constants recovered from public firmware
and public source, independently re-extracted from the committed PE.

## Upstream projects referenced (all public on GitHub)

| Project | License | What we used |
|---|---|---|
| `bacher09/pwgen-for-bios` | GPL-3.0 (per repo lineage) | public algorithm constants and 1 test vector |
| `secaicandido/bioskey` (a.k.a. `Claudio-Candido/bioskey`) | GPL-3.0-only | observed CLI/test outputs; its suffix-in-serial hypothesis is reproduced only as a labelled negative control |
| `chromebreakerdev/DellBIOSTools` | repo LICENSE | suffix UI list, 8FC8 note, `DellPfsExtract` vendored helper used once for extraction |
| `serversupdep-ai/Bin-file` | research corpus | E7A8 vectors, suffix catalogue, BIOS_IMG.rcv parts, probe/grab tooling |
| `serversupdep-ai/Zte` (this repo) | research corpus | CF1B_FINDINGS.md, emulation vectors, solution_kit tools |
| `LeRELIKT/BIOS-Generator-Patch`, `dogbert/bios-pwgen` | GPL-3.0 lineage | corroboration that 2026 offline generators still stop at E7A8 |
| `uefi_firmware` (PyPI), `pefile`, `jsbi` (npm) | their own licenses | one-off extraction / running upstream tests; not bundled here |

Pinned commits, blob SHAs and issue permalinks: `evidence/github_sources.json`.

The firmware PE in `evidence/` came from a **public Dell update image** that
was already committed to `serversupdep-ai/Bin-file` on GitHub. It is included
(38,912 bytes) solely so every table claim in the report is recomputable
offline. If the rights holder objects, remove that one file; the JSON evidence
and all tests that do not parse the PE still stand.

## Safety / authorization

* Analyze and run these tools only on machines you own or are explicitly
  authorized to service.
* No live machine, no Dell backend and no paid unlock service was contacted
  during this research.
* The tools do not generate a password for EC-era suffixes from public data —
  that is the finding, not a missing feature. Never present a guess as a
  validated master password.
* BIOS lock screens count failed attempts; stop after a couple of codes and
  use the documented routes (machine EC readout, Dell support, SPI patch).
