# Cross-machine analysis — "collect different machines of the same security"

Question (standing directive): can EC firmware collected from many different
machines with the same suffix/security/BIOS generation yield the material for
a standalone offline keygen?

**Executed 2026-09-15 on six real payloads** (OptiPlex 3090 2.0.7 / 2.27.0 /
2.30.0, 3080 2.33.0, 5080 1.34.0, 7080 1.37.0 — different machines, same
Comet-Lake desktop generation, CF1B/8FC8 security era):

| finding | value |
|---|---|
| 3090 2.27.0 vs 2.30.0 vs **5080 1.34.0 vs 7080 1.37.0** (different MODELS) | sealed EC body **byte-identical, 100.0%** of 99,648 bytes (sha256 91d5677b85ede41a…) |
| body entropy / chi² | 8.00 / 247 — pure AES (uniform band 255±22) |
| 64-byte blocks shared across DIFFERENT sealed bodies | **0** of 3,106 — per-image keys, no reuse, no differential surface |
| pre-PHCM 2.0.7-era payload | different container, staging tables only (engine not present) |

**Conclusion:** different machines of the same build ship the *same* sealed
image — collecting N machines of a build yields exactly as much information
as collecting one. The AES key that unseals it is fused in the EC's silicon
and appears in no file (all header/KDF interpretations tested — zero hits).
This reconfirms, live and byte-exact, the corpus closure (CF1B_FINDINGS
§11.7/§11.8/§11.10: 150+ payloads, 20+ machines, 4 generations).

**What WOULD complete the offline keygen** (the hunt's HIT conditions):
1. a per-build AES key leak — one leak unseals every machine on the build;
2. an EC-INTERNAL flash dump ("EC程序", RT809H direct-EC read) — the running,
   decrypted GENERATE engine;
3. a Dell-backend leak of the enrolled masters.

`cross_machine_diff.py` now runs this differential automatically on any
payload set — including everything ec_hunt.py fetches — and flags the two
breakthrough signals (shared blocks across bodies = key reuse; any
non-sealed GENERATE-era body).
