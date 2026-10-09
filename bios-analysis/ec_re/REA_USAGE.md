# REA (morluto/rea) usage record — cycle 16

User directive (2026-10-05): "Use this tool to reverse files —
https://github.com/morluto/rea". This file records exactly how REA was
integrated and where its boundaries are in this sandbox.

## Install

- `rea-agents@4.0.1` installed globally via npm (`npm install --global
  rea-agents`) — Node 22.22.3 meets REA's Node 22.19+ requirement.
- Repo: github.com/morluto/rea (MIT), TypeScript, 5k stars.

## What REA does here

- `rea providers` / `rea capabilities` / `rea doctor` — 5 providers
  registered (ghidra, hopper, native-macos, rea-artifact-graph,
  rea-dotnet-static); 16 capability records. Doctor: node OK; host
  "debian 12" unsupported (REA supports macOS 12+/Ubuntu 24.04+/Fedora
  41+/Arch/Win-Ghidra-P0); Ghidra missing (GHIDRA_INSTALL_DIR unset);
  Hopper missing.
- `rea inspect-artifact <PE>` — WORKS on the BIOS-side vault modules
  (used on `collected/OptiPlex_3090_2.0.7/pw_4_42496.efi`): returns a
  canonical Evidence bundle (sha256 subject digest, PE inventory
  substeps, artifact graph manifest).
- `rea inspect-managed-artifact <PE>` — WORKS: PE identity (machine
  0x8664/x86_64, byte length, format pe) via the rea-dotnet-static
  provider.
- `rea analyze` / `rea inspect-artifact` on raw EC firmware bins —
  correctly reports `target_unavailable` (raw blobs are not a supported
  artifact container).

## Boundaries (sandbox egress)

- REA's native instruction/decompile lane requires **Ghidra 12.1.4 +
  JDK 21**. Both release assets download from
  `release-assets.githubusercontent.com` / `objects.githubusercontent.com`,
  which are **SSL-blocked in this sandbox** (curl exit 35; `gh api`
  octet-stream redirects there too). api.github.com, github.com,
  registry.npmjs.org, pypi.org, files.pythonhosted.org and
  codeload.github.com ARE reachable; the asset CDNs are not.
- Therefore the instruction-level reversing of the EC firmware was done
  with the REA-independent complement built this cycle:
  capstone + unicorn (`ec_re/dell_ec_engine_re.py`), which is fully
  offline and emulation-verified (see EC_RE_FINDINGS.md §3).

## Verdict

REA is installed and its artifact/PE/evidence lanes are functional and
used (evidence bundles above). If this sandbox ever gains release-CDN
egress, install Ghidra 12.1.4 + JDK 21 into /tmp/tools, set
GHIDRA_INSTALL_DIR, and REA's `decompile` / `inspect-native-instruction`
/ `trace-native-values` lanes become available for the same binaries.
