# Latest-suffix master-password research — GitHub-source reconstruction

**Answer in one sentence.** As of 2026-10-27 the newest Dell lock-screen suffix
documented on GitHub is **`9ABE`** (Precision 5680 / BIOS 1.29.0,
[pwgen-for-bios #333](https://github.com/bacher09/pwgen-for-bios/issues/333),
2026-10-13), but it has **no new offline formula**: the machine's own firmware
routes `9ABE` to the embedded controller and copies the first 16 bytes of the
EC's 32-byte `GENERATE` response as the master code, while the last suffix with
a real host-side keygen algorithm is **`E7A8`** — proven here by re-extracting
the suffix tables from a real Latitude 5440 BIOS 1.28.1 image committed to
[`serversupdep-ai/Bin-file`](https://github.com/serversupdep-ai/Bin-file).

## What is in here

| File | Purpose |
|---|---|
| `INVENTED_SOLUTION.md` | **Start here for the "invent it, don't re-publish it" answer**: why a formula cannot be invented (98.72 bits/pair), the falsification engine, and the 57-query probe that either recovers the generator from your board or proves no offline one exists |
| `falsify.py` | Original hypothesis-space falsification engine: ~163k renders, 0 survivors against 3 owner-verified 8FC8 pairs, positive control recovers a planted formula at rank 1 |
| `ec_oracle_probe.py` | Chosen-query function-class probe: 57 queries recover an affine EC generator exactly; classifies nonlinear and tag-locked ECs; `--self-test` 5/5 |
| `test_invented.py` | 33 tests for the two tools above (affine recovery, PRF rejection, tag-lock, noise band, information accounting) |
| `evidence/invented_results.json` | Machine-readable output of every sweep and probe case |
| `FINAL_REPORT.md` | Full REA-style report: scope, call chains with addresses, evidence + confidence, data formats, edge cases, unknowns |
| `latest_suffix.py` | Clean, stdlib-only reconstruction: suffix catalogue, E7A8 engine, EC response renderer, dispatcher + CLI |
| `vault_inspect.py` | Stdlib-only PE inspector that re-extracts suffix descriptor tables, EC family lists, alphabets and params from a firmware module |
| `verify_sources.py` | Re-checks every pinned GitHub commit/blob SHA against `api.github.com` (2026-10-29: 25 OK / 0 SKIP / 1 GONE / 0 FAIL — `LeRELIKT/BIOS-Generator-Patch` has vanished upstream, recorded as GONE, never as a pass); offline-safe |
| `test_latest_suffix.py` | 36 tests / 68 byte-level vector comparisons — all pass, no network, no third-party packages |
| `evidence/github_sources.json` | Pinned GitHub repos/commits/blob SHAs + issue/comment permalinks |
| `evidence/firmware_5440_1281.json` | Independent extraction from the GitHub-sourced BIOS image (hashes, offsets, reproduction chain) |
| `evidence/vectors.json` | Public validation vectors, field pairs, EC render vectors, observed `bioskey` outputs |
| `evidence/DellSecurityVaultSmm_Latitude5440_1.28.1.pe` | The 38,912-byte vault module extracted from that image, so every table claim is recomputable offline |

## Quickstart

```bash
cd latest-suffix
python3 -m unittest -v test_latest_suffix.py        # 36 tests, all pass

python3 latest_suffix.py 7QJ4H42-E7A8               # last local algorithm -> 2 codes
python3 latest_suffix.py 847TJ34-9ABE               # newest suffix -> needs EC response
python3 latest_suffix.py 847TJ34-9ABE --resp 4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435
python3 latest_suffix.py 1K6Y963-8FC8 --hypothesis  # DISPROVEN guess, shown for comparison
python3 latest_suffix.py --catalog                  # every suffix + mechanism + confidence
python3 vault_inspect.py                           # re-extract tables from the committed PE
python3 verify_sources.py                          # 25 OK / 1 GONE / 0 FAIL (2026-10-29)

# the invented half
python3 falsify.py --control --info --space all    # planted formula recovered; 0 survivors on real pairs
python3 falsify.py --space wide                    # 38,416-config rotation lattice, ~30 s
python3 ec_oracle_probe.py --self-test             # affine/xorshift recovered, PRF + tag-lock rejected
python3 ec_oracle_probe.py --simulate xorshift --target 5S38Y33 --suffix 8FC8
python3 -m unittest test_invented.py               # 33 tests
```

Example output for the newest suffix:

```
Input       847TJ34-9ABE
Suffix      9ABE  (2024-2026 (newest displayed suffix on GitHub))
Mechanism   ec-verbatim  [confidence: probable]
Latest      displayed suffix 9ABE; last host-side algorithm E7A8
EC family   0xBE
NEEDS       32-byte EC GENERATE response from this exact machine
            session {21 00 03 06}; send tag (7B); send family LSB (0xBE); recv 32B; recv status
            tool: bios-analysis/solution_kit/src/dell_ec_keygen.py --render / --keygen
```

## Verdict table

| question | answer | confidence |
|---|---|---|
| Newest suffix seen on GitHub (2026-10-27) | `9ABE` — issue #333, 2026-10-13, BIOS 1.29.0 | proven (sighting) |
| Newest suffix *word in the newest host-side descriptor table* | `8FC8` (params = NULL) | proven (byte extraction; also `CF1B_FINDINGS.md` §17) |
| Newest suffix with a working offline tag→password formula | `E7A8` — two SHA-256-tailed candidates | proven (20/20 + 12/12 + field vectors; params byte-identical in the 1.28.1 image) |
| Algorithm for `9ABE` / `CF1B` / `3FE2` / `1B58` | `master = EC_GENERATE(tag, family_lsb)[0:16]` verbatim | proven (firmware emulation, 3 independent GitHub sources) |
| Algorithm for `8FC8` | `master[i] = alphabet[(resp[i]+resp[i+16]) % 72]` | proven (firmware emulation + extracted alphabet) |
| `secaicandido/bioskey` (2026-10-18) "supports" 3FE2/8FC8/CF1B/9ABE/1B58 | It reuses the E7A8 engine with the displayed suffix in the hashed serial; **fails 4/4 public 8FC8 field pairs** and contradicts the NULL encoder | disproven for 8FC8; unsupported for 9ABE |
| `8FCA`, `8FDC8`, `AE60`, `A6E0`, `0001`, `8FCE` | Reported display/state words, absent from every examined firmware suffix table | assumed |

## The invented half, in one paragraph

The transform is not in any GitHub file, so it cannot be extracted; and a 16-character
code over a 72-symbol alphabet is 98.72 bits of entropy, so it cannot be *guessed*
either — a formula printed without validation is one of 2^98.72 equally plausible
strings. What can be built instead is decisive: `falsify.py` shows the entire
"hash-and-fold the tag" family (including the published `bioskey` relabel of
`E7A8`) is falsified against the three owner-verified 8FC8 pairs while still
recovering a planted formula at rank 1; and `ec_oracle_probe.py` reduces the open
question to a binary property of the EC — `resp(tag)` affine over GF(2) or not.
If it is affine, 57 chosen queries recover the generator exactly and the latest
suffix is solved offline with nothing published; if not, the same 8 queries prove
no offline generator can exist for anyone. See `INVENTED_SOLUTION.md`.

## Scope / authorization

Static analysis of public GitHub source files, public firmware update images and
public issue threads only; no live machine and no Dell service was contacted.
Use the tools here only on hardware you own or are explicitly authorized to
service.  Repeated wrong codes can trigger a firmware lockout.
